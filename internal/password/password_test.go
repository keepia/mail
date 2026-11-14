package password

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// testPassword is a placeholder, never a real password.
const testPassword = "placeholder-pass-1"

// newHash is the format of a new hash (#95 plan, section 3): the 16-byte
// salt and the 32-byte tag in the standard alphabet without padding.
var newHash = regexp.MustCompile(`^\{ARGON2ID\}\$argon2id\$v=19\$m=65536,t=3,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

// recompute checks that the stored hash's tag is Argon2id of pw with the
// stored salt and parameters.
func recompute(t *testing.T, stored, pw string) {
	t.Helper()
	a, err := ParseArgon2ID(stored)
	if err != nil {
		t.Fatalf("ParseArgon2ID: %v", err)
	}
	key := argon2.IDKey([]byte(pw), a.Salt, a.Time, a.Memory, a.Threads, uint32(len(a.Key))) //nolint:gosec // at most 64
	if !bytes.Equal(key, a.Key) {
		t.Errorf("the tag of %s is not Argon2id of the password with its salt", stored)
	}
}

// Test 8: a new hash has exactly the section-3 format, its tag is
// Argon2id of the password with the parsed salt, and two hashes of one
// password differ (random salt).
func TestHash(t *testing.T) {
	h1, err := Hash(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{h1, h2} {
		if !newHash.MatchString(h) || len(h) != 107 {
			t.Errorf("hash %q (%d characters) does not have the format %s", h, len(h), newHash)
		}
		recompute(t, h, testPassword)
		if s, err := ValidateStored(h); err != nil || s != SchemeArgon2ID {
			t.Errorf("ValidateStored(new hash) = %q, %v", s, err)
		}
	}
	if h1 == h2 {
		t.Error("two hashes of one password are equal: the salt is not random")
	}
}

// Test 8, the encoding with a fixed salt whose base64 has both '+' and
// '/': a URL-safe alphabet ('-', '_') fails the format, so the counter-
// proof RawURLEncoding fails here every time, not only when the random
// salt happens to need one of the two characters.
func TestHashEncoding(t *testing.T) {
	salt := []byte{0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff, 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}
	h := hashWithSalt(testPassword, salt)
	const prefix = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$++++////++++////AAAAAA$"
	if !strings.HasPrefix(h, prefix) || !newHash.MatchString(h) {
		t.Errorf("hash %q, want the prefix %q and the format %s", h, prefix, newHash)
	}
	recompute(t, h, testPassword)
}

// Test 8, the encoding vector: x/crypto's own argon2id vector
// ("password", "somesalt", t=2, m=64, p=1; argon2/argon2_test.go in
// v0.59.0, made with the reference implementation) encoded as a PHC
// string gives the fixed text below, ValidateStored accepts it, and
// recomputing from the parsed string gives the vector's tag. The salt and
// the tag in that text were encoded apart from this package, with
// coreutils' base64 (padding removed).
func TestArgon2IDVector(t *testing.T) {
	tag, err := hex.DecodeString("068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7")
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeArgon2ID(Argon2ID{Memory: 64, Time: 2, Threads: 1, Salt: []byte("somesalt"), Key: tag})
	const want = "{ARGON2ID}$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3"
	if enc != want {
		t.Errorf("encoded vector %q, want %q", enc, want)
	}
	if s, err := ValidateStored(enc); err != nil || s != SchemeArgon2ID {
		t.Fatalf("ValidateStored(vector) = %q, %v", s, err)
	}
	a, err := ParseArgon2ID(enc)
	if err != nil {
		t.Fatal(err)
	}
	if a.Memory != 64 || a.Time != 2 || a.Threads != 1 || string(a.Salt) != "somesalt" {
		t.Errorf("parsed %+v", a)
	}
	recompute(t, enc, "password")
}

// accepted are stored hashes that ValidateStored accepts, one or more per
// scheme, each with its source. The doveadm ones come from `doveadm pw -s
// <scheme> -p placeholder-pass-1` in the pinned dovecot/dovecot:2.4.5
// image (docker-compose.yml), without -r (its default) unless noted.
var accepted = []struct{ source, scheme, hash string }{
	{"doveadm pw -s ARGON2ID", SchemeArgon2ID,
		"{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$VXHwODjENRPzvF5vKaDyyw$JlomXtSbd0QKwrSlsr81wRpwP8OSnlVfK6mNNLzGxmw"},
	{"x/crypto argon2 vector, PHC-encoded", SchemeArgon2ID,
		"{ARGON2ID}$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ$Bo1ismRVk2qm6+YAYLCmWHDb+j3fjUH3"},
	{"the upper bounds: M=65536, T=10, P=4, 64-byte salt and hash", SchemeArgon2ID,
		"{ARGON2ID}$argon2id$v=19$m=65536,t=10,p=4$" + strings.Repeat("A", 85) + "Q$" + strings.Repeat("A", 85) + "Q"},
	{"the lower bounds: M=8·P, T=1, 8-byte salt, 16-byte hash", SchemeArgon2ID,
		"{ARGON2ID}$argon2id$v=19$m=32,t=1,p=4$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA"},
	{"doveadm pw -s BLF-CRYPT", SchemeBlfCrypt, "{BLF-CRYPT}$2y$05$i.WA1NI7uaZfadBkPJZUdObewUbpDKqEqLWTCmSpx/H.tWCQEfOIa"},
	{"doveadm pw -s BLF-CRYPT -r 10 (mailcow's cost)", SchemeBlfCrypt, "{BLF-CRYPT}$2y$10$5knHCybOlRDCCMhUg5TEgeWvEpb5X4MBxIgbL2ITsgFpmy5CLHaBm"},
	{"doveadm pw -s SHA512-CRYPT", SchemeSHA512Crypt,
		"{SHA512-CRYPT}$6$66DQr9HcwQMSjl97$6PS9w5XT.iVs1LdEjLBLrWxsgFO2vDNc7jDiIgJ86TVASu2oNzN1HZPmfyR1eHquNJuqqHOvTbY3zFDo3aMmt/"},
	{"doveadm pw -s SHA512-CRYPT -r 10000", SchemeSHA512Crypt,
		"{SHA512-CRYPT}$6$rounds=10000$zO5HZI/GkqNcT9O5$RmUkjvuKe6vcZDMFUhsQRbZUlexkqNB75UYzYJMGhWfeefpbME1eQSMG0LaM0/bR7qWbNTVrgsReNPxs4iSDO/"},
	{"doveadm pw -s SHA256-CRYPT", SchemeSHA256Crypt, "{SHA256-CRYPT}$5$FQbovS1Fe6ioCfYW$lrcHfkYv3LHVr85B2nKdH2OC.9YDItCXvtHN0xInXb3"},
	{"doveadm pw -s SHA256-CRYPT -r 10000", SchemeSHA256Crypt,
		"{SHA256-CRYPT}$5$rounds=10000$ID.8z.VSi/r1Iv5h$wCo25GKapGbTYtCZz./nI4x3onE94xJ4MyBUMFkp6n8"},
	{"SHA-crypt with rounds at both bounds and an empty salt", SchemeSHA256Crypt,
		"{SHA256-CRYPT}$5$rounds=1000$$" + strings.Repeat("a", 43)},
	{"SHA-crypt with 500000 rounds", SchemeSHA512Crypt,
		"{SHA512-CRYPT}$6$rounds=500000$saltsaltsaltsalt$" + strings.Repeat("a", 86)},
	{"doveadm pw -s SSHA", SchemeSSHA, "{SSHA}X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xv"},
	{"doveadm pw -s SSHA256", SchemeSSHA256, "{SSHA256}9zwWyLdj6AV5vXYlMLLw/AFyms+Gy+4uFAbu5D2dyuh0/Tdf"},
	{"doveadm pw -s SSHA512", SchemeSSHA512,
		"{SSHA512}RvNkIaXOwVdz0c7Qbi6EtCT+x6IFQilBIJNYsR9N4Ety2hrSWElOmqw7aubUA6HJNJjAu54BoOPcOt/C+5YmTnh9QF0="},
	{"SSHA512 with a 64-byte salt", SchemeSSHA512, "{SSHA512}" + base64.StdEncoding.EncodeToString(make([]byte, 128))},
}

// Test 9: one accepted example per scheme, with its source.
func TestValidateStoredAccepts(t *testing.T) {
	for _, c := range accepted {
		s, err := ValidateStored(c.hash)
		if err != nil || s != c.scheme {
			t.Errorf("%s: ValidateStored = %q, %v; want %q", c.source, s, err, c.scheme)
		}
	}
	// x/crypto's bcrypt writes $2a$, the form of PHP before 5.3.7.
	h, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := ValidateStored("{BLF-CRYPT}" + string(h)); err != nil || s != SchemeBlfCrypt {
		t.Errorf("x/crypto bcrypt %s: ValidateStored = %q, %v", h, s, err)
	}
	b := strings.Replace("{BLF-CRYPT}"+string(h), "$2a$", "$2b$", 1)
	if _, err := ValidateStored(b); err != nil {
		t.Errorf("$2b$: %v", err)
	}
}

// argon is an {ARGON2ID} hash with the given parameter string, salt and
// hash fields.
func argon(params, salt, hash string) string {
	return "{ARGON2ID}$argon2id$v=19$" + params + "$" + salt + "$" + hash
}

// Valid fields for the rejected cases: a 16-byte salt and a 32-byte hash.
var (
	salt16   = base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	hash32   = base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	bcrypt53 = strings.Repeat("a", 53)
)

// rawB64 is n zero bytes in base64 without padding.
func rawB64(n int) string { return base64.RawStdEncoding.EncodeToString(make([]byte, n)) }

// Test 9: one rejected example per bound and form of section 3.
func TestValidateStoredRefuses(t *testing.T) {
	cases := []struct{ name, hash string }{
		// The common rules.
		{"empty", ""},
		{"no prefix", "$argon2id$v=19$m=65536,t=3,p=1$" + salt16 + "$" + hash32},
		{"PLAIN", "{PLAIN}" + testPassword},
		{"MD5-CRYPT", "{MD5-CRYPT}$1$saltsalt$abcdefghijklmnopqrstuv"},
		{"ARGON2I", "{ARGON2I}$argon2i$v=19$m=65536,t=3,p=1$" + salt16 + "$" + hash32},
		{"a .HEX suffix", "{SSHA.HEX}" + hex.EncodeToString(make([]byte, 24))},
		{"a .B64 suffix", "{SSHA.B64}X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xv"},
		{"lowercase scheme", "{ssha}X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xv"},
		{"a space", "{SSHA} X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xv"},
		{"a trailing newline", "{SSHA}X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xv\n"},
		{"a tab", "{SSHA}X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xv\t"},
		{"non-ASCII", "{SSHA}X9sB8iYVopRWOlxCZBJjkXwk75pbj5Xé"},
		{"513 bytes", "{SSHA512}" + base64.StdEncoding.EncodeToString(make([]byte, 378))},
		// {ARGON2ID}.
		{"argon2i under {ARGON2ID}", "{ARGON2ID}$argon2i$v=19$m=65536,t=3,p=1$" + salt16 + "$" + hash32},
		{"v=16", "{ARGON2ID}$argon2id$v=16$m=65536,t=3,p=1$" + salt16 + "$" + hash32},
		{"no version", "{ARGON2ID}$argon2id$m=65536,t=3,p=1$" + salt16 + "$" + hash32},
		{"M above 65536", argon("m=65537,t=3,p=1", salt16, hash32)},
		{"M below 8·P", argon("m=31,t=1,p=4", salt16, hash32)},
		{"T 0", argon("m=65536,t=0,p=1", salt16, hash32)},
		{"T above 10", argon("m=65536,t=11,p=1", salt16, hash32)},
		{"P 0", argon("m=65536,t=3,p=0", salt16, hash32)},
		{"P above 4", argon("m=65536,t=3,p=5", salt16, hash32)},
		{"parameters out of order", argon("t=3,m=65536,p=1", salt16, hash32)},
		{"a leading zero", argon("m=065536,t=3,p=1", salt16, hash32)},
		{"a sign", argon("m=+65536,t=3,p=1", salt16, hash32)},
		{"a fourth parameter", argon("m=65536,t=3,p=1,k=1", salt16, hash32)},
		{"salt of 7 bytes", argon("m=65536,t=3,p=1", rawB64(7), hash32)},
		{"salt of 65 bytes", argon("m=65536,t=3,p=1", rawB64(65), hash32)},
		{"hash of 15 bytes", argon("m=65536,t=3,p=1", salt16, rawB64(15))},
		{"hash of 65 bytes", argon("m=65536,t=3,p=1", salt16, rawB64(65))},
		{"padded base64", argon("m=65536,t=3,p=1", salt16+"==", hash32)},
		{"URL-safe base64", argon("m=65536,t=3,p=1", "-_"+salt16[2:], hash32)},
		{"non-canonical base64", argon("m=65536,t=3,p=1", salt16[:21]+"B", hash32)},
		{"a missing field", "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$" + salt16},
		{"an extra field", argon("m=65536,t=3,p=1", salt16, hash32) + "$x"},
		// {BLF-CRYPT}.
		{"bcrypt cost 03", "{BLF-CRYPT}$2y$03$" + bcrypt53},
		{"bcrypt cost 14", "{BLF-CRYPT}$2y$14$" + bcrypt53},
		{"bcrypt one-digit cost", "{BLF-CRYPT}$2y$5$" + bcrypt53 + "a"},
		{"bcrypt $2x$", "{BLF-CRYPT}$2x$10$" + bcrypt53},
		{"bcrypt $2$", "{BLF-CRYPT}$2$10$" + bcrypt53 + "a"},
		{"bcrypt 52 characters", "{BLF-CRYPT}$2y$10$" + bcrypt53[1:]},
		{"bcrypt 54 characters", "{BLF-CRYPT}$2y$10$" + bcrypt53 + "a"},
		{"bcrypt a character outside its alphabet", "{BLF-CRYPT}$2y$10$" + bcrypt53[1:] + "+"},
		// {SHA512-CRYPT} and {SHA256-CRYPT}.
		{"rounds 999", "{SHA512-CRYPT}$6$rounds=999$salt$" + strings.Repeat("a", 86)},
		{"rounds 500001", "{SHA512-CRYPT}$6$rounds=500001$salt$" + strings.Repeat("a", 86)},
		{"rounds with a leading zero", "{SHA512-CRYPT}$6$rounds=05000$salt$" + strings.Repeat("a", 86)},
		{"rounds without a value", "{SHA512-CRYPT}$6$rounds=$salt$" + strings.Repeat("a", 86)},
		{"salt of 17 characters", "{SHA512-CRYPT}$6$" + strings.Repeat("s", 17) + "$" + strings.Repeat("a", 86)},
		{"SHA-512 hash of 85 characters", "{SHA512-CRYPT}$6$salt$" + strings.Repeat("a", 85)},
		{"SHA-512 hash of 87 characters", "{SHA512-CRYPT}$6$salt$" + strings.Repeat("a", 87)},
		{"SHA-256 hash of 42 characters", "{SHA256-CRYPT}$5$salt$" + strings.Repeat("a", 42)},
		{"$5$ under {SHA512-CRYPT}", "{SHA512-CRYPT}$5$salt$" + strings.Repeat("a", 43)},
		{"$6$ under {SHA256-CRYPT}", "{SHA256-CRYPT}$6$salt$" + strings.Repeat("a", 86)},
		{"SHA-crypt without a salt field", "{SHA256-CRYPT}$5$" + strings.Repeat("a", 43)},
		{"SHA-crypt a character outside its alphabet", "{SHA256-CRYPT}$5$salt$" + strings.Repeat("a", 42) + "+"},
		{"SHA-crypt salt with a character outside its alphabet", "{SHA256-CRYPT}$5$sa*t$" + strings.Repeat("a", 43)},
		// The SSHA family.
		{"SSHA without padding", "{SSHA}" + base64.RawStdEncoding.EncodeToString(make([]byte, 22))},
		{"SSHA without a salt", "{SSHA}" + base64.StdEncoding.EncodeToString(make([]byte, 20))},
		{"SSHA with a 65-byte salt", "{SSHA}" + base64.StdEncoding.EncodeToString(make([]byte, 85))},
		{"SSHA256 without a salt", "{SSHA256}" + base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{"SSHA512 without a salt", "{SSHA512}" + base64.StdEncoding.EncodeToString(make([]byte, 64))},
		{"SSHA512 with a 65-byte salt", "{SSHA512}" + base64.StdEncoding.EncodeToString(make([]byte, 129))},
		{"SSHA URL-safe", "{SSHA}X9sB8iYVopRWOlxCZBJjkXwk75pbj5X_"},
	}
	for _, c := range cases {
		s, err := ValidateStored(c.hash)
		if err == nil {
			t.Errorf("%s: ValidateStored(%q) accepted it as %q", c.name, c.hash, s)
			continue
		}
		if c.hash != "" && strings.Contains(err.Error(), c.hash) {
			t.Errorf("%s: the error quotes the hash: %v", c.name, err)
		}
		if len(c.hash) > 16 && strings.Contains(err.Error(), c.hash[len(c.hash)-16:]) {
			t.Errorf("%s: the error quotes part of the hash: %v", c.name, err)
		}
	}
}

// The password rule (CD6), in Go; the CLI cases of test 10 run through
// keepia-mail.
func TestCheck(t *testing.T) {
	for _, ok := range []string{
		strings.Repeat("a", 12), strings.Repeat("ä", 12), strings.Repeat("a", 256), strings.Repeat("ß", 256), "with a space 1",
	} {
		if err := Check(ok); err != nil {
			t.Errorf("Check(%d characters): %v", len([]rune(ok)), err)
		}
	}
	for name, bad := range map[string]string{
		"empty":          "",
		"11 characters":  strings.Repeat("a", 11),
		"257 characters": strings.Repeat("ß", 257),
		"NUL":            "placeholder\x00pass",
		"ESC":            "placeholder\x1bpass",
		"DEL":            "placeholder\x7fpass",
		"a C1 control":   "placeholder\u0085pass",
		"a tab":          "placeholder\tpass",
		"invalid UTF-8":  "placeholder\xffpass",
	} {
		err := Check(bad)
		if err == nil {
			t.Errorf("Check(%s) accepted it", name)
			continue
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("Check(%s): the error quotes the password: %v", name, err)
		}
	}
}

func TestScheme(t *testing.T) {
	for in, want := range map[string]string{
		"{ARGON2ID}$argon2id$x": "ARGON2ID", "{SSHA}x": "SSHA", "SSHA}x": "", "{SSHA": "", "": "",
	} {
		if got := Scheme(in); got != want {
			t.Errorf("Scheme(%q) = %q, want %q", in, got, want)
		}
	}
}
