package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrRevoked is the refusal of a certificate on its anchor's revocation
// list.
var ErrRevoked = errors.New("certificate revoked")

// ErrPeer is wrapped by every refusal of VerifyClient and VerifyServer
// that is not ErrRevoked or ErrCRLExpired.
var ErrPeer = errors.New("peer certificate refused")

// Identity is who a client certificate names.
type Identity struct {
	Purpose  Purpose
	ServerID int64
}

// VerifyClient checks a client's certificate chain at a listener that
// trusts anchor for the given purposes, with the anchor's current
// revocation list crl (for tls.Config.VerifyConnection; peer is the
// presented chain, leaf first). It accepts only a leaf that
//
//   - chains to anchor alone, with any other presented certificate as an
//     intermediate (the anchor's pathlen:0 refuses every intermediate);
//   - is valid at now;
//   - is an ECDSA P-256 end-entity certificate (CA:FALSE);
//   - has exactly one EKU, clientAuth (Go and OpenSSL read a missing EKU
//     as any use);
//   - has exactly one SAN, the URI keepia:<purpose>:<server-id>, with a
//     purpose of anchor's that is in purposes;
//   - is not on crl, which must be anchor's and valid at now: without a
//     valid list there is no connection.
func VerifyClient(peer []*x509.Certificate, anchor *x509.Certificate, purposes []Purpose, crl *CRL, now time.Time) (Identity, error) {
	if err := oneAnchor(purposes); err != nil {
		return Identity{}, err
	}
	leaf, err := verifyChain(peer, anchor, x509.ExtKeyUsageClientAuth, "", now)
	if err != nil {
		return Identity{}, err
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return Identity{}, fmt.Errorf("%w: a client certificate needs exactly one URI SAN and no other", ErrPeer)
	}
	purpose, id, err := parseClientURI(leaf.URIs[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrPeer, err)
	}
	if !slices.Contains(purposes, purpose) {
		return Identity{}, fmt.Errorf("%w: the purpose %s is not accepted here", ErrPeer, purpose)
	}
	if err := crl.checkCurrent(anchor, leaf.SerialNumber, now); err != nil {
		return Identity{}, err
	}
	return Identity{Purpose: purpose, ServerID: id}, nil
}

// oneAnchor checks a listener's accepted purposes: at least one, all
// client purposes of the same anchor. A listener trusts one anchor, so a
// purpose of another anchor in its list is a configuration error.
func oneAnchor(purposes []Purpose) error {
	if len(purposes) == 0 {
		return errors.New("listener configuration: no accepted purpose")
	}
	var first AnchorName
	for i, p := range purposes {
		pr, ok := profiles[p]
		if !ok || pr.server {
			return fmt.Errorf("listener configuration: %q is not a client purpose", p)
		}
		if i == 0 {
			first = pr.anchor
		} else if pr.anchor != first {
			return fmt.Errorf("listener configuration: the purposes %s and %s belong to different anchors", purposes[0], p)
		}
	}
	return nil
}

// VerifyServer checks a gate's certificate chain from a caller that trusts
// anchor (the service anchor) and expects the gate dnsName, with the
// anchor's current revocation list crl (CD30). It accepts only a leaf that
// chains to anchor alone, is valid at now, is an ECDSA P-256 end-entity
// certificate with exactly one EKU, serverAuth, and exactly one SAN, the
// DNS name dnsName, and is not on crl, which must be valid at now.
func VerifyServer(peer []*x509.Certificate, anchor *x509.Certificate, dnsName string, crl *CRL, now time.Time) error {
	leaf, err := VerifyServerChain(peer, anchor, dnsName, now)
	if err != nil {
		return err
	}
	return crl.checkCurrent(anchor, leaf.SerialNumber, now)
}

// VerifyServerChain is VerifyServer without the revocation check, and
// returns the leaf: for the first step of a join (#96 C5), which checks
// the leaf against the pinned anchor before it has a list, and then
// against the fetched list (join.CheckLeaf). Every other caller uses
// VerifyServer.
func VerifyServerChain(peer []*x509.Certificate, anchor *x509.Certificate, dnsName string, now time.Time) (*x509.Certificate, error) {
	leaf, err := verifyChain(peer, anchor, x509.ExtKeyUsageServerAuth, dnsName, now)
	if err != nil {
		return nil, err
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != dnsName ||
		len(leaf.URIs) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, fmt.Errorf("%w: a server certificate needs exactly one SAN, the DNS name %s", ErrPeer, dnsName)
	}
	return leaf, nil
}

// verifyChain verifies the chain peer against anchor alone at now, for
// the extended key usage eku and, when dnsName is set, that host name.
// It returns the leaf after the end-entity checks every leaf must pass:
// P-256, CA:FALSE, and exactly one EKU, eku.
func verifyChain(peer []*x509.Certificate, anchor *x509.Certificate, eku x509.ExtKeyUsage, dnsName string, now time.Time) (*x509.Certificate, error) {
	if len(peer) == 0 || peer[0] == nil {
		return nil, fmt.Errorf("%w: no certificate", ErrPeer)
	}
	leaf := peer[0]
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	inter := x509.NewCertPool()
	for _, c := range peer[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		DNSName:       dnsName,
		KeyUsages:     []x509.ExtKeyUsage{eku},
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeer, err)
	}
	if _, err := p256(leaf.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeer, err)
	}
	if leaf.IsCA {
		return nil, fmt.Errorf("%w: a CA certificate as a leaf", ErrPeer)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != eku || len(leaf.UnknownExtKeyUsage) != 0 {
		return nil, fmt.Errorf("%w: the certificate must have exactly one extended key usage", ErrPeer)
	}
	return leaf, nil
}

// NeedsRenewal tells whether a leaf is due for renewal at now: from its
// NotBefore + 10 days on (CD17). The holder then renews with a new key.
func NeedsRenewal(leaf *x509.Certificate, now time.Time) bool {
	return !now.Before(leaf.NotBefore.Add(RenewAfter))
}
