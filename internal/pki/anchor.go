// Package pki is Keepia Mail's certificate library (#96, CD11–CD17): the
// four trust anchors, the leaf profiles, issuing a leaf for a public key,
// the revocation lists, and the checks that listeners and callers run on a
// peer's certificate. It is pure: it holds no keys of its own and reads no
// database; internal/secrets keeps the anchor keys.
//
// Every key is ECDSA P-256 and every signature ECDSA with SHA-256 (CD11).
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// AnchorName names one of the four trust anchors (architecture §5a).
type AnchorName string

// The four anchors. Each one signs only its own purposes (CD13), so a
// listener that trusts one anchor accepts no certificate of another.
const (
	AnchorStoreClient     AnchorName = "store-client"
	AnchorGroupwareClient AnchorName = "groupware-client"
	AnchorAgent           AnchorName = "agent"
	AnchorService         AnchorName = "service"
)

// Anchors lists the four anchors in a fixed order.
var Anchors = []AnchorName{AnchorStoreClient, AnchorGroupwareClient, AnchorAgent, AnchorService}

// Lifetimes (CD12, CD16, CD17).
const (
	// AnchorLifetime is an anchor's validity, from AnchorBackdate before
	// its creation.
	AnchorLifetime = 10 * 365 * 24 * time.Hour
	// AnchorBackdate is how far an anchor's NotBefore lies in the past.
	AnchorBackdate = time.Hour
	// LeafLifetime is a leaf's validity after its issuance.
	LeafLifetime = 30 * 24 * time.Hour
	// LeafBackdate is how far a leaf's NotBefore lies before its issuance.
	LeafBackdate = 5 * time.Minute
	// RenewAfter is the age, from NotBefore, at which NeedsRenewal is true.
	RenewAfter = 10 * 24 * time.Hour
	// CRLLifetime is a revocation list's nextUpdate after its thisUpdate.
	CRLLifetime = 7 * 24 * time.Hour
	// CRLClockSkew is how far a list's thisUpdate may lie in the future.
	CRLClockSkew = 5 * time.Minute
)

// Anchor is a trust anchor: its self-signed CA certificate and its key.
type Anchor struct {
	Name   AnchorName
	Cert   *x509.Certificate
	Signer crypto.Signer
}

// ErrNotP256 is returned for a key that is not ECDSA P-256.
var ErrNotP256 = errors.New("the key is not ECDSA P-256")

// NewAnchor creates the anchor name for the deployment deploymentID: a new
// P-256 key and a self-signed CA certificate (CD12) with
//
//   - CA:TRUE and pathlen:0 (critical; MaxPathLenZero, so the constraint is
//     really encoded and no intermediate can exist),
//   - KeyUsage keyCertSign and cRLSign (critical),
//   - a SubjectKeyId and a 128-bit random serial,
//   - the subject CN=Keepia Mail <name> anchor, O=<deployment id in hex>,
//   - a validity of 10 years from now − 1 h.
func NewAnchor(name AnchorName, deploymentID []byte, now time.Time) (*Anchor, error) {
	if !knownAnchor(name) {
		return nil, fmt.Errorf("unknown anchor %q", name)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	skid := sha256.Sum256(pubDER)
	now = now.UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Keepia Mail " + string(name) + " anchor",
			Organization: []string{hex.EncodeToString(deploymentID)},
		},
		NotBefore:             now.Add(-AnchorBackdate),
		NotAfter:              now.Add(-AnchorBackdate + AnchorLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid[:20],
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Anchor{Name: name, Cert: cert, Signer: key}, nil
}

// LoadAnchor builds the anchor name from its certificate (DER) and its
// private key (PKCS#8 DER). It checks that the certificate is a P-256 CA
// certificate and that the key belongs to it.
func LoadAnchor(name AnchorName, certDER, keyPKCS8 []byte) (*Anchor, error) {
	if !knownAnchor(name) {
		return nil, fmt.Errorf("unknown anchor %q", name)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("anchor %s: certificate: %w", name, err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, fmt.Errorf("anchor %s: the certificate is not a CA", name)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("anchor %s: certificate: %w", name, ErrNotP256)
	}
	k, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		// The parse error names no key bytes.
		return nil, fmt.Errorf("anchor %s: the private key does not parse", name)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("anchor %s: private key: %w", name, ErrNotP256)
	}
	if !key.PublicKey.Equal(pub) {
		return nil, fmt.Errorf("anchor %s: the private key does not belong to the certificate", name)
	}
	return &Anchor{Name: name, Cert: cert, Signer: key}, nil
}

func knownAnchor(name AnchorName) bool {
	for _, a := range Anchors {
		if a == name {
			return true
		}
	}
	return false
}

// randomSerial is a positive 128-bit random serial number.
func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	// The top bit set keeps the length fixed; DER adds a zero byte, so the
	// number stays positive.
	b[0] |= 0x80
	return new(big.Int).SetBytes(b), nil
}

// p256 returns pub as a P-256 key, or ErrNotP256.
func p256(pub crypto.PublicKey) (*ecdsa.PublicKey, error) {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, ErrNotP256
	}
	return k, nil
}
