package secrets

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func testSealer(t *testing.T) *sealer {
	t.Helper()
	s, err := newSealer(testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// S1. Seal and open round-trip; the nonce is random.
func TestSealRoundTrip(t *testing.T) {
	s := testSealer(t)
	pub, pt := []byte("public part"), []byte("the secret")
	a := s.seal("anchor/agent", 1, pub, pt)
	b := s.seal("anchor/agent", 1, pub, pt)
	if bytes.Equal(a, b) {
		t.Error("two seals of the same value are equal")
	}
	if len(a) != 12+len(pt)+16 || bytes.Contains(a, pt) {
		t.Errorf("sealed value: %d bytes", len(a))
	}
	got, err := s.open("anchor/agent", 1, pub, s.id[:], a)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %q, %v", got, err)
	}
	if got, err := s.open(NameStoreMaster, 2, nil, s.id[:], s.seal(NameStoreMaster, 2, nil, pt)); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open without a public part: %q, %v", got, err)
	}
}

// S2. A flipped bit anywhere in the sealed value gives ErrTampered.
func TestSealTampered(t *testing.T) {
	s := testSealer(t)
	sealed := s.seal("mail-crypt", 1, []byte("pub"), []byte("private key"))
	for i := range len(sealed) * 8 {
		c := bytes.Clone(sealed)
		c[i/8] ^= 1 << (i % 8)
		if _, err := s.open("mail-crypt", 1, []byte("pub"), s.id[:], c); !errors.Is(err, ErrTampered) {
			t.Fatalf("bit %d flipped: %v, want ErrTampered", i, err)
		}
	}
	if _, err := s.open("mail-crypt", 1, []byte("pub"), s.id[:], sealed[:len(sealed)-1]); !errors.Is(err, ErrTampered) {
		t.Errorf("truncated: %v", err)
	}
}

// S3, S4. A row copied to another name or version, or with a swapped
// public part, does not open (AAD).
func TestSealBindsTheRow(t *testing.T) {
	s := testSealer(t)
	pub := []byte("certificate A")
	sealed := s.seal("anchor/agent", 1, pub, []byte("key A"))
	for name, open := range map[string]func() error{
		"another name": func() error {
			_, err := s.open("anchor/service", 1, pub, s.id[:], sealed)
			return err
		},
		"another version": func() error {
			_, err := s.open("anchor/agent", 2, pub, s.id[:], sealed)
			return err
		},
		"another public part": func() error {
			_, err := s.open("anchor/agent", 1, []byte("certificate B"), s.id[:], sealed)
			return err
		},
		"no public part": func() error {
			_, err := s.open("anchor/agent", 1, nil, s.id[:], sealed)
			return err
		},
	} {
		if err := open(); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: %v, want ErrTampered", name, err)
		}
	}
}

// S5. Another KEK gives ErrWrongKEK by id, naming both ids, before any
// decryption; with a forged id, GCM still fails.
func TestSealWrongKEK(t *testing.T) {
	a, b := testSealer(t), testSealer(t)
	sealed := a.seal(NameStoreMaster, 1, nil, []byte("pw"))
	_, err := b.open(NameStoreMaster, 1, nil, a.id[:], sealed)
	if !errors.Is(err, ErrWrongKEK) || !strings.Contains(err.Error(), a.id.String()) || !strings.Contains(err.Error(), b.id.String()) {
		t.Errorf("another KEK: %v, want ErrWrongKEK naming %s and %s", err, a.id, b.id)
	}
	if _, err := b.open(NameStoreMaster, 1, nil, b.id[:], sealed); !errors.Is(err, ErrTampered) {
		t.Errorf("forged id: %v, want ErrTampered", err)
	}
}

// The KEK id is HKDF of the KEK, distinct per KEK and stable.
func TestKEKID(t *testing.T) {
	k := testKEK(t)
	again, err := newKEK(k.key[:])
	if err != nil || again.id != k.id {
		t.Fatalf("id not stable: %v", err)
	}
	if testKEK(t).id == k.id {
		t.Error("two KEKs with one id")
	}
	if bytes.Contains(k.key[:], k.id[:]) {
		t.Error("the id is part of the key")
	}
	// The id has its own HKDF label (CD2, CD3): it is not the start of
	// the derived sealing key, so publishing the id reveals no key byte.
	sealing, err := hkdf.Key(sha256.New, k.key[:], nil, labelSecrets, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.id[:], sealing[:len(k.id)]) {
		t.Error("the KEK id is the derived sealing key's first 16 bytes")
	}
}
