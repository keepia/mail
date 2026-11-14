package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// Names of the control secrets (CD9). Each anchor's key is
// anchor/<anchor name>.
const (
	// NameStoreMaster is the store master credential's password (CD18).
	NameStoreMaster = "store-master"
	// NameMailCrypt is the global mail_crypt key pair (CD19).
	NameMailCrypt = "mail-crypt"
	// MasterUser is the store master credential's user name; not a
	// secret.
	MasterUser = "keepia-master"
)

// AnchorSecretName is the control secret that holds the anchor's key.
func AnchorSecretName(a pki.AnchorName) string { return "anchor/" + string(a) }

// secretNames are the six secrets of a keyring, sorted.
func secretNames() []string {
	names := []string{NameStoreMaster, NameMailCrypt}
	for _, a := range pki.Anchors {
		names = append(names, AnchorSecretName(a))
	}
	slices.Sort(names)
	return names
}

// material is the plaintext of a keyring: what the bootstrap generates
// and what loading opens.
type material struct {
	deploymentID []byte
	anchors      map[pki.AnchorName]*pki.Anchor
	master       string
	mailCrypt    *ecdsa.PrivateKey
}

// generate creates the contents of a new keyring (CD9): a random 16-byte
// deployment id, the four anchors, the store master password (32 random
// bytes as base64url, 43 characters) and the mail_crypt P-256 key pair.
func generate(now time.Time) (*material, error) {
	m := &material{deploymentID: make([]byte, 16), anchors: map[pki.AnchorName]*pki.Anchor{}}
	if _, err := rand.Read(m.deploymentID); err != nil {
		return nil, err
	}
	for _, name := range pki.Anchors {
		a, err := pki.NewAnchor(name, m.deploymentID, now)
		if err != nil {
			return nil, fmt.Errorf("anchor %s: %w", name, err)
		}
		m.anchors[name] = a
	}
	pw := make([]byte, 32)
	if _, err := rand.Read(pw); err != nil {
		return nil, err
	}
	m.master = base64.RawURLEncoding.EncodeToString(pw)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.mailCrypt = key
	return m, nil
}

// rows seals the material under s as version 1 of each secret.
func (m *material) rows(s *sealer) ([]store.SecretRow, error) {
	var out []store.SecretRow
	add := func(name string, public, plaintext []byte) {
		out = append(out, store.SecretRow{
			Name: name, Version: 1, Public: public, KEKID: s.id[:],
			Sealed: s.seal(name, 1, public, plaintext),
		})
	}
	for _, name := range pki.Anchors {
		a := m.anchors[name]
		key, err := x509.MarshalPKCS8PrivateKey(a.Signer)
		if err != nil {
			return nil, err
		}
		add(AnchorSecretName(name), a.Cert.Raw, key)
	}
	add(NameStoreMaster, nil, []byte(m.master))
	priv, err := x509.MarshalPKCS8PrivateKey(m.mailCrypt)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(m.mailCrypt.Public())
	if err != nil {
		return nil, err
	}
	add(NameMailCrypt, pub, priv)
	return out, nil
}

// openRows opens the newest version of each of the six secrets under s.
// A missing or extra name, or a row that does not open, is an error.
func openRows(s *sealer, deploymentID []byte, rows []store.SecretRow) (*material, error) {
	var got []string
	for _, r := range rows {
		got = append(got, r.Name)
	}
	slices.Sort(got)
	if want := secretNames(); !slices.Equal(got, want) {
		return nil, fmt.Errorf("%w: the database holds the secrets %v, want %v", ErrSecretsIncomplete, got, want)
	}
	m := &material{deploymentID: deploymentID, anchors: map[pki.AnchorName]*pki.Anchor{}}
	for _, r := range rows {
		pt, err := s.open(r.Name, r.Version, r.Public, r.KEKID, r.Sealed)
		if err != nil {
			return nil, err
		}
		switch r.Name {
		case NameStoreMaster:
			m.master = string(pt)
		case NameMailCrypt:
			k, err := x509.ParsePKCS8PrivateKey(pt)
			key, ok := k.(*ecdsa.PrivateKey)
			if err != nil || !ok || key.Curve != elliptic.P256() {
				return nil, fmt.Errorf("%w: %s v%d is not a P-256 key", ErrSecretsIncomplete, r.Name, r.Version)
			}
			pub, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil || !slices.Equal(pub, r.Public) {
				return nil, fmt.Errorf("%w: %s v%d: the public key does not match the private key", ErrSecretsIncomplete, r.Name, r.Version)
			}
			m.mailCrypt = key
		default:
			name := pki.AnchorName(r.Name[len("anchor/"):])
			a, err := pki.LoadAnchor(name, r.Public, pt)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrSecretsIncomplete, err)
			}
			m.anchors[name] = a
		}
	}
	return m, nil
}

// ErrSecretsIncomplete means the database's secrets are not the six of a
// keyring, or one of them, once opened, is not what its name says.
var ErrSecretsIncomplete = errors.New("control secrets incomplete or malformed")

// mailCryptPEM returns the mail_crypt key pair in the forms Dovecot reads
// (CD19): the private key as PEM "PRIVATE KEY" (PKCS#8) and the public
// key as PEM "PUBLIC KEY" (SPKI), both unencrypted.
func mailCryptPEM(key *ecdsa.PrivateKey) (private, public []byte, err error) {
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), nil
}
