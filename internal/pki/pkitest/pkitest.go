// Package pkitest provides anchors and certificate requests for tests,
// generated at run time (no key is ever committed). Only tests import it.
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
)

// Keys is a set of the four anchors with their keys (pki.AnchorKeys).
type Keys map[pki.AnchorName]*pki.Anchor

// Anchor returns the anchor name.
func (k Keys) Anchor(name pki.AnchorName) *pki.Anchor { return k[name] }

// NewKeys creates the four anchors of a new deployment at now.
func NewKeys(tb testing.TB, now time.Time) Keys {
	tb.Helper()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		tb.Fatal(err)
	}
	k := Keys{}
	for _, name := range pki.Anchors {
		a, err := pki.NewAnchor(name, id, now)
		if err != nil {
			tb.Fatal(err)
		}
		k[name] = a
	}
	return k
}

// CSR returns a P-256 certificate request (DER) and its key. It asks for
// a DNS name and a URI, which issuance must ignore (CD15).
func CSR(tb testing.TB) ([]byte, *ecdsa.PrivateKey) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "control.keepia.internal"},
		DNSNames: []string{"control.keepia.internal"},
	}, key)
	if err != nil {
		tb.Fatal(err)
	}
	return der, key
}
