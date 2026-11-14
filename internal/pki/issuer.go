package pki

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/keepia/mail/internal/store"
)

// AnchorKeys hands out the anchors with their keys; secrets.Keyring is
// one.
type AnchorKeys interface {
	Anchor(name AnchorName) *Anchor
}

// Refusals of IssueForServer and RevokeServer. Each is wrapped with the
// server's name.
var (
	// ErrServerRemoved: the server was removed; nothing is issued to it.
	ErrServerRemoved = errors.New("the server was removed")
	// ErrRemoveControl: the control server cannot be removed.
	ErrRemoveControl = errors.New("the control server cannot be removed")
	// ErrStoreHoldsMailboxes: a store server that still holds mailboxes
	// cannot be removed; moving mailboxes comes in 1.1.0 (CD23).
	ErrStoreHoldsMailboxes = errors.New("the server's stores still hold mailboxes")
)

// Purpose names in the certificates table: a Purpose, or this one for the
// control gate's certificate, which has no server (CD34).
const controlGatePurpose = "control-gate"

// IssueForServer issues a leaf of purpose for pub to the server
// serverName and records it, in one transaction that reads the server
// row FOR SHARE, so it waits for a concurrent `server remove` and then
// refuses (ErrServerRemoved). role is the gate's role for PurposeGate and
// ignored otherwise. The policy is CheckPolicy's: never the control
// gate's name or a purpose of a later release.
func IssueForServer(ctx context.Context, st *store.Store, a AnchorKeys, serverName string, purpose Purpose, role string, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	var cert *x509.Certificate
	err := st.PKIWrite(ctx, "certificate.issue", func(ctx context.Context, tx *store.PKITx) (string, map[string]any, error) {
		sv, err := tx.LockServer(ctx, serverName, false)
		if err != nil {
			return "", nil, err
		}
		cert, err = IssueInTx(ctx, tx, a, sv, purpose, role, pub, now)
		if err != nil {
			return "", nil, err
		}
		return serverName, map[string]any{"purpose": string(purpose), "serial": fmt.Sprintf("%x", cert.SerialNumber)}, nil
	})
	return cert, err
}

// IssueInTx is IssueForServer inside a transaction that already locked
// the server row sv (a join's redeem, which locks it FOR UPDATE).
func IssueInTx(ctx context.Context, tx *store.PKITx, a AnchorKeys, sv store.Server, purpose Purpose, role string, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	if sv.RemovedAt != nil {
		return nil, fmt.Errorf("server %s: %w", sv.Name, ErrServerRemoved)
	}
	var (
		l   Leaf
		err error
	)
	if purpose == PurposeGate {
		l, err = GateLeaf(role, sv.Name, sv.ID)
	} else {
		l, err = ClientLeaf(purpose, sv.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	if err := CheckPolicy(l, sv.Roles); err != nil {
		return nil, fmt.Errorf("server %s: %w", sv.Name, err)
	}
	anchorName, _ := l.Purpose.Anchor()
	anchor := a.Anchor(anchorName)
	if anchor == nil {
		return nil, fmt.Errorf("no anchor %s", anchorName)
	}
	cert, err := Issue(anchor, l, pub, now)
	if err != nil {
		return nil, err
	}
	if err := record(ctx, tx, anchorName, sv.ID, string(l.Purpose), l.DNSName, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// record inserts cert into the certificates table.
func record(ctx context.Context, tx *store.PKITx, anchor AnchorName, serverID int64, purpose, dnsName string, cert *x509.Certificate) error {
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return tx.InsertCertificate(ctx, store.CertificateRow{
		Serial: cert.SerialNumber.Bytes(), Anchor: string(anchor), ServerID: serverID, Purpose: purpose, DNSName: dnsName,
		SPKISHA256: spki[:], NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, DER: cert.Raw,
	})
}

// RevokeServer is `server remove` (CD23, CD36, C13, X3), in one READ
// COMMITTED transaction:
//
//  1. the servers row FOR UPDATE, so a concurrent mailbox insert (T7
//     reads it FOR SHARE) either commits first and is counted below, or
//     waits and then sees removed_at;
//  2. a control server, or one already removed, is refused;
//  3. the CRL lock (LockClassCRL);
//  4. the mailboxes on the server's stores are counted: a store that
//     still holds mailboxes is refused (ErrStoreHoldsMailboxes);
//  5. every certificate of the server is revoked (cessationOfOperation),
//     its unused tokens are invalidated, and removed_at is set;
//  6. all four lists are reissued (Reissue's steps 3-6).
//
// Statement 4 runs after the row lock is granted, so under READ
// COMMITTED it sees a mailbox committed while it waited. A failure
// anywhere rolls back the revocation together with its lists. The row is
// kept, for the lists' entries.
func RevokeServer(ctx context.Context, st *store.Store, a AnchorKeys, serverName string, now time.Time) (revoked int, err error) {
	h := hooksFrom(ctx)
	err = st.PKIWrite(ctx, "server.remove", func(ctx context.Context, tx *store.PKITx) (string, map[string]any, error) {
		sv, err := tx.LockServer(ctx, serverName, true)
		if err != nil {
			return "", nil, err
		}
		if sv.RemovedAt != nil {
			return "", nil, fmt.Errorf("server %s: %w", serverName, ErrServerRemoved)
		}
		if slices.Contains(sv.Roles, RoleControl) {
			return "", nil, fmt.Errorf("server %s: %w", serverName, ErrRemoveControl)
		}
		if err := tx.LockCRL(ctx); err != nil {
			return "", nil, err
		}
		n, err := tx.CountServerMailboxes(ctx, sv.ID)
		if err != nil {
			return "", nil, err
		}
		if n > 0 {
			return "", nil, fmt.Errorf("server %s: %w (%d)", serverName, ErrStoreHoldsMailboxes, n)
		}
		h.call(h.afterMailboxCount)
		serials, err := tx.RevokeServerCertificates(ctx, sv.ID, now, ReasonCessationOfOperation)
		if err != nil {
			return "", nil, err
		}
		tokens, err := tx.InvalidateServerTokens(ctx, sv.ID, now)
		if err != nil {
			return "", nil, err
		}
		if err := tx.SetServerRemoved(ctx, sv.ID, now); err != nil {
			return "", nil, err
		}
		if err := reissueLocked(ctx, tx, a, now, h); err != nil {
			return "", nil, err
		}
		revoked = len(serials)
		return serverName, map[string]any{"revoked_certificates": len(serials), "invalidated_tokens": tokens}, nil
	})
	return revoked, err
}
