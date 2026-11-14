package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// Errors of Open.
var (
	// ErrWrongKEK: the row was sealed under another KEK (by its id).
	ErrWrongKEK = errors.New("wrong KEK")
	// ErrTampered: the row does not open under this KEK, name, version
	// and public part: changed, copied to another name or version, or
	// paired with another public part.
	ErrTampered = errors.New("sealed secret does not open: tampered, copied or swapped")
)

// sealer seals and opens control secrets under one KEK (CD2): AES-256-GCM
// with a random 96-bit nonce per value, under a key derived from the KEK
// with HKDF-SHA256 and the label keepia-mail/v1/secrets.
type sealer struct {
	id   KEKID
	aead cipher.AEAD
}

func newSealer(k *KEK) (*sealer, error) {
	key, err := hkdf.Key(sha256.New, k.key[:], nil, labelSecrets, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &sealer{id: k.id, aead: aead}, nil
}

// aad binds a sealed value to its row: keepia-mail/v1/secret ‖ 0x00 ‖ name
// ‖ 0x00 ‖ version (8 bytes, big-endian) ‖ kek_id ‖ SHA-256(public part,
// or empty). The name never holds 0x00 (the table's CHECK), and every
// other field has a fixed length, so the encoding is unambiguous.
func aad(name string, version int, kekID KEKID, public []byte) []byte {
	pub := sha256.Sum256(public)
	b := make([]byte, 0, 64+len(name))
	b = append(b, "keepia-mail/v1/secret"...)
	b = append(b, 0)
	b = append(b, name...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, uint64(version)) //nolint:gosec // version >= 1 (CHECK)
	b = append(b, kekID[:]...)
	b = append(b, pub[:]...)
	return b
}

// seal seals plaintext as version of name with its public part: nonce ‖
// ciphertext ‖ tag.
func (s *sealer) seal(name string, version int, public, plaintext []byte) []byte {
	// NewGCMWithRandomNonce takes no nonce: it draws a random one and
	// prepends it to the output.
	return s.aead.Seal(nil, nil, plaintext, aad(name, version, s.id, public)) //nolint:gosec // G407: the nonce is random, see above
}

// open opens a row sealed as version of name with its public part, sealed
// under the KEK rowKEKID. A row of another KEK gives ErrWrongKEK, naming
// both ids, before any decryption is tried; a row that does not open
// gives ErrTampered.
func (s *sealer) open(name string, version int, public, rowKEKID, sealed []byte) ([]byte, error) {
	if len(rowKEKID) != len(s.id) || subtle.ConstantTimeCompare(rowKEKID, s.id[:]) != 1 {
		return nil, fmt.Errorf("%w: %s v%d was sealed under the KEK %x, the KEK file is %s", ErrWrongKEK, name, version, rowKEKID, s.id)
	}
	pt, err := s.aead.Open(nil, nil, sealed, aad(name, version, s.id, public))
	if err != nil {
		return nil, fmt.Errorf("%w: %s v%d", ErrTampered, name, version)
	}
	return pt, nil
}
