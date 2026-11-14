package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"github.com/keepia/mail/internal/store"
)

// IssueControlGate issues the control gate's server certificate (CD34):
// a new P-256 key and a leaf of the service anchor with serverAuth, the
// one DNS SAN control.keepia.internal and no URI SAN, valid 30 days. It
// records the leaf with no server (purpose control-gate) and returns the
// leaf and its key. Only serve calls it, for the bundle it writes into
// the volume control-gate-pki; IssueForServer never issues this name.
func IssueControlGate(ctx context.Context, st *store.Store, a AnchorKeys, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	anchor := a.Anchor(AnchorService)
	if anchor == nil {
		return nil, nil, errors.New("no service anchor")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	l := ControlGateLeaf()
	cert, err := Issue(anchor, l, key.Public(), now)
	if err != nil {
		return nil, nil, err
	}
	err = st.PKIWrite(ctx, "control-gate.issue", func(ctx context.Context, tx *store.PKITx) (string, map[string]any, error) {
		if err := record(ctx, tx, AnchorService, 0, controlGatePurpose, l.DNSName, cert); err != nil {
			return "", nil, err
		}
		return ControlGateName, map[string]any{"not_after": cert.NotAfter.UTC().Format(time.RFC3339)}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
