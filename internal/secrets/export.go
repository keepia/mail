package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// The export format, version 1 (CD25 with N6): a PEM block of this type
// whose headers, in this order, are Version, KDF, KDF-Params, Salt,
// KEK-Id and Created. The body is AES-256-GCM (a 12-byte random nonce,
// the ciphertext, a 16-byte tag) under Argon2id(passphrase, salt) with the
// header text as the additional data, so a changed header does not open.
const (
	ExportType   = "KEEPIA MAIL SECRETS EXPORT"
	exportKDF    = "argon2id"
	exportParams = "m=65536,t=3,p=4"
	saltSize     = 16
)

// Argon2id's parameters for version 1: RFC 9106's second recommended
// option (64 MiB, 3 passes, 4 lanes). They are fixed, so an export
// cannot ask for more memory.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
)

// Passphrase bounds (CD25).
const (
	MinPassphraseChars = 16
	MaxPassphraseBytes = 1024
)

// Errors of the export and restore.
var (
	// ErrPassphrase: the passphrase is too short or too long.
	ErrPassphrase = errors.New("passphrase refused")
	// ErrExportFormat: the input is not a version 1 export.
	ErrExportFormat = errors.New("not a keepia-mail secrets export (version 1)")
	// ErrExportOpen: the export does not open: a wrong passphrase, or a
	// changed header or body.
	ErrExportOpen = errors.New("the export does not open: wrong passphrase, or the export was changed")
	// ErrRestoreRefused is wrapped by every refusal of Restore.
	ErrRestoreRefused = errors.New("restore refused")
)

// CheckPassphrase checks a passphrase's length: at least 16 characters
// and at most 1024 bytes.
func CheckPassphrase(p []byte) error {
	if len(p) > MaxPassphraseBytes {
		return fmt.Errorf("%w: longer than %d bytes", ErrPassphrase, MaxPassphraseBytes)
	}
	if utf8.RuneCount(p) < MinPassphraseChars {
		return fmt.Errorf("%w: shorter than %d characters", ErrPassphrase, MinPassphraseChars)
	}
	return nil
}

// exportHeader is the export's header, in its fixed order.
type exportHeader struct {
	salt    []byte
	kekID   KEKID
	created time.Time
}

// text is the canonical header text, the additional data: every header
// line in CD25's order as "Key: value\n".
func (h exportHeader) text() string {
	return "Version: 1\n" +
		"KDF: " + exportKDF + "\n" +
		"KDF-Params: " + exportParams + "\n" +
		"Salt: " + base64.StdEncoding.EncodeToString(h.salt) + "\n" +
		"KEK-Id: " + h.kekID.String() + "\n" +
		"Created: " + h.created.UTC().Format(time.RFC3339) + "\n"
}

// exportPayload is the sealed body: the KEK, the deployment id and every
// control_secrets row as stored, so an export plus its passphrase hold
// every secret and, with a dump, restore the running state.
type exportPayload struct {
	Version      int            `json:"version"`
	KEK          []byte         `json:"kek"`
	DeploymentID []byte         `json:"deployment_id"`
	CreatedAt    time.Time      `json:"created_at"`
	Secrets      []exportSecret `json:"secrets"`
}

type exportSecret struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Public  []byte `json:"public"`
	KEKID   []byte `json:"kek_id"`
	Sealed  []byte `json:"sealed"`
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func exportAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Export is `secrets export` (CD25, C9, X2). Under the bootstrap lock
// held shared, it opens the secrets as Read does, then derives the key
// with Argon2id inside the shared hash lock (store.WithHashLock: the
// bootstrap lock before the hash lock), seals the KEK, the deployment id
// and every control_secrets row, writes the export to w, and only then
// sets last_export_at. A hash lock not granted in time wraps
// store.ErrLockTimeout.
func Export(ctx context.Context, st *store.Store, c Config, passphrase []byte, w io.Writer) error {
	if err := CheckPassphrase(passphrase); err != nil {
		return err
	}
	timeout := c.LockTimeout
	if timeout == 0 {
		timeout = ReadLockTimeout
	}
	sess, err := st.LockSecrets(ctx, false, timeout)
	if err != nil {
		return err
	}
	defer sess.Close(ctx)
	s, err := readState(ctx, sess, c)
	if err != nil {
		return err
	}
	if err := s.readable(c); err != nil {
		return err
	}
	kr, err := loadKeyring(ctx, sess, s.keyring, s.kek)
	if err != nil {
		return err
	}
	rows, err := sess.AllSecrets(ctx)
	if err != nil {
		return err
	}
	p := exportPayload{Version: 1, KEK: s.kek.key[:], DeploymentID: kr.deploymentID, CreatedAt: kr.createdAt}
	for _, r := range rows {
		p.Secrets = append(p.Secrets, exportSecret{Name: r.Name, Version: r.Version, Public: r.Public, KEKID: r.KEKID, Sealed: r.Sealed})
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	h := exportHeader{salt: make([]byte, saltSize), kekID: s.kek.id, created: c.now().UTC().Truncate(time.Second)}
	if _, err := rand.Read(h.salt); err != nil {
		return err
	}
	var key []byte
	if err := st.WithHashLock(ctx, func() error {
		key = deriveKey(passphrase, h.salt)
		return nil
	}); err != nil {
		return hashLockErr(err)
	}
	out, err := sealExport(h, key, plain)
	if err != nil {
		return err
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	return sess.SetLastExport(ctx, c.now())
}

// sealExport seals plain under key with h's text as the additional data
// and returns the export's PEM text, its headers in CD25's order.
func sealExport(h exportHeader, key, plain []byte) ([]byte, error) {
	aead, err := exportAEAD(key)
	if err != nil {
		return nil, err
	}
	body := aead.Seal(nil, nil, plain, []byte(h.text())) //nolint:gosec // G407: NewGCMWithRandomNonce draws the nonce
	var out bytes.Buffer
	out.WriteString("-----BEGIN " + ExportType + "-----\n")
	out.WriteString(h.text())
	out.WriteString("\n")
	enc := base64.StdEncoding.EncodeToString(body)
	for len(enc) > 64 {
		out.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	out.WriteString(enc + "\n")
	out.WriteString("-----END " + ExportType + "-----\n")
	return out.Bytes(), nil
}

// hashLockErr names the hash lock in a lock timeout (C9).
func hashLockErr(err error) error {
	if errors.Is(err, store.ErrLockTimeout) {
		return fmt.Errorf("another keepia-mail command is hashing a password; try again: %w", err)
	}
	return err
}

// parsedExport is an export whose header checked out, not yet opened.
type parsedExport struct {
	header exportHeader
	body   []byte
}

// parseExport reads a version 1 export. It refuses any other type,
// version, KDF or KDF parameters before anything is derived.
func parseExport(in []byte) (*parsedExport, error) {
	b, rest := pem.Decode(in)
	if b == nil || b.Type != ExportType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrExportFormat
	}
	want := []string{"Created", "KDF", "KDF-Params", "KEK-Id", "Salt", "Version"}
	var got []string
	for k := range b.Headers {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) || b.Headers["Version"] != "1" || b.Headers["KDF"] != exportKDF {
		return nil, ErrExportFormat
	}
	if b.Headers["KDF-Params"] != exportParams {
		return nil, fmt.Errorf("%w: KDF-Params must be %s", ErrExportFormat, exportParams)
	}
	var h exportHeader
	salt, err := base64.StdEncoding.Strict().DecodeString(b.Headers["Salt"])
	if err != nil || len(salt) != saltSize {
		return nil, fmt.Errorf("%w: Salt", ErrExportFormat)
	}
	h.salt = salt
	id, err := hex.DecodeString(b.Headers["KEK-Id"])
	if err != nil || len(id) != len(h.kekID) {
		return nil, fmt.Errorf("%w: KEK-Id", ErrExportFormat)
	}
	copy(h.kekID[:], id)
	if h.created, err = time.Parse(time.RFC3339, b.Headers["Created"]); err != nil {
		return nil, fmt.Errorf("%w: Created", ErrExportFormat)
	}
	return &parsedExport{header: h, body: b.Bytes}, nil
}

// open derives the key and opens the export. The caller holds the hash
// lock (deriveKey runs Argon2id).
func (e *parsedExport) open(key []byte) (*exportPayload, error) {
	aead, err := exportAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nil, e.body, []byte(e.header.text()))
	if err != nil {
		return nil, ErrExportOpen
	}
	var p exportPayload
	if err := json.Unmarshal(plain, &p); err != nil || p.Version != 1 {
		return nil, ErrExportFormat
	}
	return &p, nil
}

// Restore is `secrets restore` (CD26 with C1, C3, C4 and C9). It writes
// only the KEK file, and only when that file is missing, no kek.new is in
// the way, and the database's keyring belongs to the export:
//
//  1. under the bootstrap lock held exclusively, the KEK file must be
//     absent and the keyring present with the export's KEK id;
//  2. Argon2id runs inside the hash lock, and the export is opened;
//  3. the KEK id is recomputed from the exported KEK, and the database's
//     sealed secrets must open under it (C4): a forged header or payload
//     id does not pass;
//  4. the KEK is written through the bootstrap's own path: kek.new with
//     O_EXCL|O_NOFOLLOW and fsync, linked to kek, then the directory is
//     synced.
//
// It never replaces a KEK and never writes a database row; every refusal
// wraps ErrRestoreRefused and leaves the files as they were. The operator
// then restarts keepia.
func Restore(ctx context.Context, st *store.Store, c Config, passphrase, export []byte) (KEKID, error) {
	refuse := func(format string, args ...any) (KEKID, error) {
		return KEKID{}, fmt.Errorf("%w: %s", ErrRestoreRefused, fmt.Sprintf(format, args...))
	}
	if err := CheckPassphrase(passphrase); err != nil {
		return KEKID{}, err
	}
	e, err := parseExport(export)
	if err != nil {
		return KEKID{}, err
	}
	timeout := c.LockTimeout
	if timeout == 0 {
		timeout = ReadLockTimeout
	}
	sess, err := st.LockSecrets(ctx, true, timeout)
	if err != nil {
		return KEKID{}, err
	}
	defer sess.Close(ctx)
	s, err := readState(ctx, sess, c)
	if err != nil {
		return KEKID{}, err
	}
	switch {
	case s.kek != nil || s.kekErr != nil:
		return refuse("%s exists; restore never replaces a KEK", c.KEKFile)
	case s.newPresent:
		return refuse("%s exists; see docs/development/index.md, \"Control secrets\"", c.newPath())
	case s.keyring == nil:
		return refuse("the database holds no control secrets; restore the database first (a full restore comes with 0.6.0)")
	case !slices.Equal(e.header.kekID[:], s.keyring.KEKID):
		return refuse("the export is of the KEK %s, but the database's secrets are sealed under the KEK %x", e.header.kekID, s.keyring.KEKID)
	}
	var key []byte
	if err := st.WithHashLock(ctx, func() error {
		key = deriveKey(passphrase, e.header.salt)
		return nil
	}); err != nil {
		return KEKID{}, hashLockErr(err)
	}
	p, err := e.open(key)
	if err != nil {
		return KEKID{}, err
	}
	kek, err := newKEK(p.KEK)
	if err != nil {
		return refuse("the export holds no valid KEK")
	}
	if !slices.Equal(kek.id[:], s.keyring.KEKID) || !slices.Equal(p.DeploymentID, s.keyring.DeploymentID) {
		return refuse("the exported KEK (id %s) or deployment is not the database's", kek.id)
	}
	if _, err := loadKeyring(ctx, sess, s.keyring, kek); err != nil {
		return refuse("the database's secrets do not open under the exported KEK: %v", err)
	}
	if err := writeNew(c.newPath(), kek); err != nil {
		return KEKID{}, err
	}
	if err := linkInPlace(c.newPath(), c.KEKFile); err != nil {
		return KEKID{}, err
	}
	return kek.id, nil
}

// Status is what `secrets status` shows (CD27): ids, times and
// fingerprints, never a secret value.
type Status struct {
	KEKID        KEKID
	DeploymentID []byte
	CreatedAt    time.Time
	// LastExportAt is nil for never.
	LastExportAt *time.Time
	Anchors      []AnchorStatus
	// MailCryptSHA256 is the SHA-256 of the mail_crypt public key (SPKI).
	MailCryptSHA256 [32]byte
	MasterPresent   bool
}

// AnchorStatus is one anchor's SPKI SHA-256 and expiry.
type AnchorStatus struct {
	Name       pki.AnchorName
	SPKISHA256 [32]byte
	NotAfter   time.Time
}

// ReadStatus opens the secrets as Read does and returns their status.
func ReadStatus(ctx context.Context, st *store.Store, c Config) (*Status, error) {
	kr, err := Read(ctx, st, c)
	if err != nil {
		return nil, err
	}
	s := &Status{
		KEKID: kr.KEKID(), DeploymentID: kr.DeploymentID(), CreatedAt: kr.CreatedAt(),
		LastExportAt: kr.LastExportAt(), MasterPresent: kr.HasMasterPassword(),
	}
	for _, name := range pki.Anchors {
		a := kr.Anchor(name)
		s.Anchors = append(s.Anchors, AnchorStatus{Name: name, SPKISHA256: sha256.Sum256(a.Cert.RawSubjectPublicKeyInfo), NotAfter: a.Cert.NotAfter})
	}
	pub, err := kr.MailCryptPublicDER()
	if err != nil {
		return nil, err
	}
	s.MailCryptSHA256 = sha256.Sum256(pub)
	return s, nil
}

// Text is the status as the command prints it.
func (s *Status) Text() string {
	var b strings.Builder
	last := "never"
	if s.LastExportAt != nil {
		last = s.LastExportAt.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(&b, "kek_id         %s\n", s.KEKID)
	fmt.Fprintf(&b, "deployment_id  %x\n", s.DeploymentID)
	fmt.Fprintf(&b, "created        %s\n", s.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "last_export    %s\n", last)
	for _, a := range s.Anchors {
		fmt.Fprintf(&b, "anchor %-16s spki_sha256 %x  expires %s\n", a.Name, a.SPKISHA256, a.NotAfter.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "mail_crypt     public_sha256 %x\n", s.MailCryptSHA256)
	master := "absent"
	if s.MasterPresent {
		master = "present"
	}
	fmt.Fprintf(&b, "store_master   %s (user %s)\n", master, MasterUser)
	return b.String()
}
