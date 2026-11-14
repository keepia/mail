package password

import (
	"crypto/sha1" //nolint:gosec // SSHA is SHA-1 by definition; this measures its cost
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// BenchmarkHash is the cost of one new password hash (#95 plan, section
// 10): go test -run '^$' -bench BenchmarkHash -benchmem ./internal/password
func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Hash(testPassword); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyBounds is the cost of verifying one imported hash of each
// family at its upper bound (revision 2, N7), so that #99's budget rests
// on measured figures. SHA-crypt is approximated by its round loop:
// 500000 digests of a 64+16-byte input, because neither the standard
// library nor x/crypto implements it; #99 measures its real
// implementation.
func BenchmarkVerifyBounds(b *testing.B) {
	pw, salt := []byte(testPassword), make([]byte, 16)
	b.Run("ARGON2ID_m65536_t10_p4", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			argon2.IDKey(pw, salt, 10, 65536, 4, 32)
		}
	})
	b.Run("BLF-CRYPT_cost13", func(b *testing.B) {
		h, err := bcrypt.GenerateFromPassword(pw, 13)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := bcrypt.CompareHashAndPassword(h, pw); err != nil {
				b.Fatal(err)
			}
		}
	})
	in := make([]byte, 64+16)
	b.Run("SHA512-CRYPT_rounds500000_approx", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for range 500000 {
				d := sha512.Sum512(in)
				in[0] = d[0]
			}
		}
	})
	b.Run("SHA256-CRYPT_rounds500000_approx", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for range 500000 {
				d := sha256.Sum256(in)
				in[0] = d[0]
			}
		}
	})
	b.Run("SSHA512_64byte_salt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sha512.Sum512(append(pw, make([]byte, 64)...))
		}
	})
	b.Run("SSHA_64byte_salt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sha1.Sum(append(pw, make([]byte, 64)...)) //nolint:gosec // see the import
		}
	})
}
