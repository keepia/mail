// Package password writes new password hashes (Argon2id) and validates
// imported ones, in Dovecot's stored form: a scheme prefix such as
// {ARGON2ID} followed by the scheme's string (#95 plan, section 3).
//
// No error of this package contains a password or a hash: every message
// is a fixed text that names only the scheme and the rule.
package password

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// The parameters of a new hash: Argon2id with 64 MiB, 3 passes and one
// lane, a 16-byte salt and a 32-byte tag. p = 1 is what Dovecot's
// ARGON2ID scheme (libsodium's crypto_pwhash_str) writes and reads.
const (
	argonVersion = argon2.Version // 0x13, "v=19"
	argonMemory  = 64 * 1024      // KiB
	argonTime    = 3
	argonThreads = 1
	argonSalt    = 16
	argonKey     = 32
)

// The schemes of a stored hash.
const (
	SchemeArgon2ID    = "ARGON2ID"
	SchemeBlfCrypt    = "BLF-CRYPT"
	SchemeSHA256Crypt = "SHA256-CRYPT"
	SchemeSHA512Crypt = "SHA512-CRYPT"
	SchemeSSHA        = "SSHA"
	SchemeSSHA256     = "SSHA256"
	SchemeSSHA512     = "SSHA512"
)

// MaxStored is the longest stored hash, in bytes (the schema's CHECK).
const MaxStored = 512

// The password rule (CD6): 12 to 256 characters of valid UTF-8, without
// NUL or any other control character.
const (
	MinLength = 12
	MaxLength = 256
)

// b64 is the base64 of PHC strings and libsodium: the standard alphabet
// without padding, and strict, so that a string has one encoding only.
var b64 = base64.RawStdEncoding.Strict()

// Hash returns the stored form of a new Argon2id hash of pw:
//
//	{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$<salt>$<tag>
//
// with a random 16-byte salt and the 32-byte tag, both in base64 without
// padding (22 and 43 characters). It takes about 64 MiB while it runs and
// keeps no reference to that memory or to the tag once it returns: the
// caller frees it (store.WithHashLock). Hash does not check pw against the
// password rule; Check does.
func Hash(pw string) (string, error) {
	salt := make([]byte, argonSalt)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("read random salt: " + err.Error())
	}
	return hashWithSalt(pw, salt), nil
}

// hashWithSalt is Hash with the given salt; tests use a fixed one.
func hashWithSalt(pw string, salt []byte) string {
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKey)
	return EncodeArgon2ID(Argon2ID{
		Memory: argonMemory, Time: argonTime, Threads: argonThreads, Salt: salt, Key: key,
	})
}

// Argon2ID is a parsed {ARGON2ID} hash (always argon2id, version 19).
type Argon2ID struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	Salt    []byte
	Key     []byte
}

// EncodeArgon2ID is the stored form of a: the {ARGON2ID} prefix and the
// PHC string.
func EncodeArgon2ID(a Argon2ID) string {
	return "{" + SchemeArgon2ID + "}$argon2id$v=" + strconv.Itoa(argonVersion) +
		"$m=" + strconv.FormatUint(uint64(a.Memory), 10) +
		",t=" + strconv.FormatUint(uint64(a.Time), 10) +
		",p=" + strconv.FormatUint(uint64(a.Threads), 10) +
		"$" + b64.EncodeToString(a.Salt) + "$" + b64.EncodeToString(a.Key)
}

// ParseArgon2ID parses a stored {ARGON2ID} hash within the import bounds
// (ValidateStored).
func ParseArgon2ID(stored string) (Argon2ID, error) {
	if err := checkStoredText(stored); err != nil {
		return Argon2ID{}, err
	}
	rest, ok := strings.CutPrefix(stored, "{"+SchemeArgon2ID+"}")
	if !ok {
		return Argon2ID{}, errors.New("not an {ARGON2ID} hash")
	}
	return parseArgon2ID(rest)
}

// Scheme returns the scheme of a stored hash, the name between its
// leading braces ({ARGON2ID}... gives ARGON2ID), or "" if it has none.
func Scheme(stored string) string {
	rest, ok := strings.CutPrefix(stored, "{")
	if !ok {
		return ""
	}
	scheme, _, ok := strings.Cut(rest, "}")
	if !ok {
		return ""
	}
	return scheme
}

// ValidateStored checks an imported hash and returns its scheme. It
// accepts only these forms, within these bounds (#95 plan, section 3),
// so that verifying one costs at most a few times an Argon2id write:
//
//   - {ARGON2ID}$argon2id$v=19$m=M,t=T,p=P$salt$hash, base64 without
//     padding: 8·P ≤ M ≤ 65536, 1 ≤ T ≤ 10, 1 ≤ P ≤ 4, a salt of 8 to 64
//     bytes and a hash of 16 to 64 bytes;
//   - {BLF-CRYPT}$2a$, $2b$ or $2y$, a two-digit cost from 04 to 13, $,
//     then 53 characters of [./A-Za-z0-9];
//   - {SHA512-CRYPT}$6$ and {SHA256-CRYPT}$5$, an optional rounds=N$ with
//     1000 ≤ N ≤ 500000, a salt of 0 to 16 characters of [./0-9A-Za-z],
//     $, then a hash of 86 or 43 such characters;
//   - {SSHA}, {SSHA256} and {SSHA512}: standard base64 with padding of the
//     digest (20, 32 or 64 bytes) and a salt of 1 to 64 bytes.
//
// Everything else is refused: other schemes ({PLAIN}, {MD5-CRYPT},
// {ARGON2I}, ...), a missing prefix, .HEX or .B64 suffixes, white space or
// other bytes outside printable ASCII, and more than 512 bytes.
func ValidateStored(stored string) (string, error) {
	if err := checkStoredText(stored); err != nil {
		return "", err
	}
	scheme := Scheme(stored)
	rest := strings.TrimPrefix(stored, "{"+scheme+"}")
	var err error
	switch scheme {
	case SchemeArgon2ID:
		_, err = parseArgon2ID(rest)
	case SchemeBlfCrypt:
		err = checkBcrypt(rest)
	case SchemeSHA512Crypt:
		err = checkSHACrypt(scheme, rest, "$6$", 86)
	case SchemeSHA256Crypt:
		err = checkSHACrypt(scheme, rest, "$5$", 43)
	case SchemeSSHA:
		err = checkSSHA(scheme, rest, 20)
	case SchemeSSHA256:
		err = checkSSHA(scheme, rest, 32)
	case SchemeSSHA512:
		err = checkSSHA(scheme, rest, 64)
	case "":
		return "", errors.New("the hash has no scheme prefix such as {ARGON2ID}")
	default:
		return "", errors.New("the hash scheme is not supported: use ARGON2ID, BLF-CRYPT, SHA512-CRYPT, SHA256-CRYPT, SSHA, SSHA256 or SSHA512")
	}
	if err != nil {
		return "", err
	}
	return scheme, nil
}

// checkStoredText checks what every stored hash must be: at most
// MaxStored bytes of printable ASCII without spaces.
func checkStoredText(s string) error {
	if len(s) > MaxStored {
		return errors.New("the hash is longer than 512 bytes")
	}
	if s == "" {
		return errors.New("the hash is empty")
	}
	for i := range len(s) {
		if s[i] < '!' || s[i] > '~' {
			return errors.New("the hash may contain only printable ASCII without white space")
		}
	}
	return nil
}

// parseArgon2ID parses the PHC string after {ARGON2ID}.
func parseArgon2ID(s string) (Argon2ID, error) {
	bad := func(what string) (Argon2ID, error) {
		return Argon2ID{}, errors.New("invalid {ARGON2ID} hash: " + what)
	}
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return bad("want $argon2id$v=19$m=M,t=T,p=P$salt$hash")
	}
	if parts[2] != "v=19" {
		return bad("the version must be v=19")
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return bad("want the parameters m=M,t=T,p=P")
	}
	m, okM := param(params[0], "m=", 65536)
	t, okT := param(params[1], "t=", 10)
	p, okP := param(params[2], "p=", 4)
	if !okM || !okT || !okP {
		return bad("want the parameters m=M,t=T,p=P with M ≤ 65536, T ≤ 10 and P ≤ 4")
	}
	if t < 1 || p < 1 || m < 8*p {
		return bad("want 1 ≤ T, 1 ≤ P and 8·P ≤ M")
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return bad("the salt must be 8 to 64 bytes in base64 without padding")
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return bad("the hash must be 16 to 64 bytes in base64 without padding")
	}
	return Argon2ID{Memory: uint32(m), Time: uint32(t), Threads: uint8(p), Salt: salt, Key: key}, nil //nolint:gosec // bounded above
}

// param parses name=N with a decimal N from 0 to limit, without a sign or
// leading zeros.
func param(s, name string, limit uint64) (uint64, bool) {
	v, ok := strings.CutPrefix(s, name)
	if !ok {
		return 0, false
	}
	return decimal(v, limit)
}

// decimal parses a decimal from 0 to limit, without a sign or leading
// zeros.
func decimal(v string, limit uint64) (uint64, bool) {
	if v == "" || len(v) > 10 || (len(v) > 1 && v[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > limit {
		return 0, false
	}
	return n, true
}

// cryptChars tells whether s is only of crypt's alphabet [./0-9A-Za-z].
func cryptChars(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c != '.' && c != '/' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// checkBcrypt checks $2a$, $2b$ or $2y$, a cost of 04 to 13, $ and 53
// characters (22 of salt, 31 of hash).
func checkBcrypt(s string) error {
	bad := errors.New("invalid {BLF-CRYPT} hash: want $2a$, $2b$ or $2y$, a two-digit cost from 04 to 13, $ and 53 characters of [./A-Za-z0-9]")
	if len(s) != 60 || s[0] != '$' || s[1] != '2' || (s[2] != 'a' && s[2] != 'b' && s[2] != 'y') || s[3] != '$' || s[6] != '$' {
		return bad
	}
	if s[4] < '0' || s[4] > '9' || s[5] < '0' || s[5] > '9' {
		return bad
	}
	if cost := int(s[4]-'0')*10 + int(s[5]-'0'); cost < 4 || cost > 13 {
		return bad
	}
	if !cryptChars(s[7:]) {
		return bad
	}
	return nil
}

// checkSHACrypt checks SHA-crypt: prefix ($5$ or $6$), an optional
// rounds=N$ (1000 to 500000), a salt of 0 to 16 crypt characters, $, and a
// hash of hashLen crypt characters.
func checkSHACrypt(scheme, s, prefix string, hashLen int) error {
	bad := errors.New("invalid {" + scheme + "} hash: want " + prefix + ", an optional rounds=N$ with N from 1000 to 500000, a salt of up to 16 characters, $ and a hash of " +
		strconv.Itoa(hashLen) + " characters of [./0-9A-Za-z]")
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return bad
	}
	if r, ok := strings.CutPrefix(rest, "rounds="); ok {
		n, after, ok := strings.Cut(r, "$")
		if !ok {
			return bad
		}
		if v, ok := decimal(n, 500000); !ok || v < 1000 {
			return bad
		}
		rest = after
	}
	salt, hash, ok := strings.Cut(rest, "$")
	if !ok || len(salt) > 16 || len(hash) != hashLen || !cryptChars(salt) || !cryptChars(hash) {
		return bad
	}
	return nil
}

// checkSSHA checks standard base64 with padding of a digest of digestLen
// bytes and a salt of 1 to 64 bytes.
func checkSSHA(scheme, s string, digestLen int) error {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) < digestLen+1 || len(b) > digestLen+64 {
		return errors.New("invalid {" + scheme + "} hash: want standard base64 of the " +
			strconv.Itoa(digestLen) + "-byte digest and a salt of 1 to 64 bytes")
	}
	return nil
}

// Check checks a new password against the password rule (CD6): 12 to
// 256 characters of valid UTF-8, with no NUL or other control character.
// Its error never contains the password.
func Check(pw string) error {
	if !utf8.ValidString(pw) {
		return errors.New("the password is not valid UTF-8")
	}
	n := utf8.RuneCountInString(pw)
	if n < MinLength {
		return errors.New("the password is shorter than 12 characters")
	}
	if n > MaxLength {
		return errors.New("the password is longer than 256 characters")
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return errors.New("the password contains a control character (such as NUL, a tab or ESC)")
		}
	}
	return nil
}
