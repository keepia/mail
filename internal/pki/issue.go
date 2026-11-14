package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Issue signs a leaf certificate for pub with the anchor a (CD13, CD17).
// Every field comes from the profile of l, nothing from the requester:
//
//   - exactly one EKU: serverAuth for a gate, clientAuth otherwise;
//   - KeyUsage digitalSignature and CA:FALSE, both critical;
//   - a 128-bit random serial and the anchor's AuthorityKeyId;
//   - a client certificate has exactly one URI SAN and no DNS SAN, a
//     server certificate exactly one DNS SAN and no URI SAN;
//   - valid from now − 5 min to now + 30 days, clamped to the anchor's
//     NotAfter, so a leaf never outlives its anchor.
//
// pub must be ECDSA P-256, and l's purpose must belong to a's anchor.
func Issue(a *Anchor, l Leaf, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	key, err := p256(pub)
	if err != nil {
		return nil, err
	}
	pr, ok := profiles[l.Purpose]
	if !ok {
		return nil, fmt.Errorf("unknown purpose %q", l.Purpose)
	}
	if pr.anchor != a.Name {
		return nil, fmt.Errorf("the purpose %s belongs to the anchor %s, not %s", l.Purpose, pr.anchor, a.Name)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now = now.UTC().Truncate(time.Second)
	notAfter := now.Add(LeafLifetime)
	if notAfter.After(a.Cert.NotAfter) {
		notAfter = a.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: l.CommonName},
		NotBefore:             now.Add(-LeafBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	if pr.server {
		if l.DNSName == "" || l.URI != nil {
			return nil, errors.New("a server certificate needs exactly one DNS name and no URI")
		}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{l.DNSName}
	} else {
		if l.URI == nil || l.DNSName != "" {
			return nil, errors.New("a client certificate needs exactly one URI and no DNS name")
		}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tmpl.URIs = []*url.URL{l.URI}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, key, a.Signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ErrCSR is wrapped by CSRPublicKey's refusals.
var ErrCSR = errors.New("certificate request refused")

// CSRPublicKey checks a certificate request (DER) and returns only its
// public key (CD15): the request must parse, its signature must verify,
// and its key must be ECDSA P-256. Its subject, SANs and extensions are
// ignored; Issue takes every field from the profile.
func CSRPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not parse", ErrCSR)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: bad signature", ErrCSR)
	}
	key, err := p256(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCSR, err)
	}
	return key, nil
}
