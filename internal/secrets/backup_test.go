package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// testPass is a test passphrase of more than 16 characters.
var testPass = []byte("correct horse battery staple")

// exported bootstraps a deployment and exports it with testPass.
func exported(t *testing.T) (*store.Store, string, Config, []byte) {
	t.Helper()
	st, dbURL := newDB(t)
	c := testConfig(t)
	bootstrap(t, st, c)
	var out bytes.Buffer
	if err := Export(context.Background(), st, c, testPass, &out); err != nil {
		t.Fatal(err)
	}
	return st, dbURL, c, out.Bytes()
}

// openExport parses and opens an export with pass.
func openExport(t *testing.T, export, pass []byte) (*exportPayload, error) {
	t.Helper()
	e, err := parseExport(export)
	if err != nil {
		return nil, err
	}
	return e.open(deriveKey(pass, e.header.salt))
}

// E1, E6: an export opens to the KEK and every row as stored, its header
// is in CD25's order, and it sets last_export_at.
func TestExportRoundTrip(t *testing.T) {
	st, dbURL, c, export := exported(t)
	text := string(export)
	order := []string{"Version: 1\n", "KDF: argon2id\n", "KDF-Params: m=65536,t=3,p=4\n", "Salt: ", "KEK-Id: ", "Created: "}
	last := 0
	for _, h := range order {
		i := strings.Index(text, h)
		if i < last {
			t.Fatalf("header %q out of order:\n%s", h, text)
		}
		last = i
	}
	p, err := openExport(t, export, testPass)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := defaultFS().load(c.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.KEK, kek.key[:]) || len(p.Secrets) != 6 || len(p.DeploymentID) != 16 {
		t.Errorf("payload: KEK equal %v, %d secrets", bytes.Equal(p.KEK, kek.key[:]), len(p.Secrets))
	}
	if n := count(t, dbURL, "secret_keyring WHERE last_export_at IS NOT NULL"); n != 1 {
		t.Error("last_export_at not set")
	}
	kr, err := Read(context.Background(), st, c)
	if err != nil || !kr.Exported() {
		t.Errorf("after the export: exported %v, %v", kr != nil && kr.Exported(), err)
	}
}

// E2, E3, E4: a wrong passphrase, a changed header (KDF-Params, KEK-Id,
// Created) and a flipped bit in the body do not open.
func TestExportRefusesChanges(t *testing.T) {
	_, _, _, export := exported(t)
	if _, err := openExport(t, export, []byte("the wrong passphrase, long enough")); !errors.Is(err, ErrExportOpen) {
		t.Errorf("wrong passphrase: %v", err)
	}
	e, err := parseExport(export)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseExport(bytes.Replace(export, []byte("m=65536,t=3,p=4"), []byte("m=262144,t=3,p=4"), 1)); !errors.Is(err, ErrExportFormat) {
		t.Errorf("KDF-Params changed: %v, want ErrExportFormat before any derivation", err)
	}
	key := deriveKey(testPass, e.header.salt)
	other := e.header.kekID
	other[0] ^= 1
	for name, changed := range map[string][]byte{
		"KEK-Id":  bytes.Replace(export, []byte(e.header.kekID.String()), []byte(other.String()), 1),
		"Created": bytes.Replace(export, []byte(e.header.created.Format(time.RFC3339)), []byte(e.header.created.Add(time.Second).Format(time.RFC3339)), 1),
	} {
		pe, err := parseExport(changed)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := pe.open(key); !errors.Is(err, ErrExportOpen) {
			t.Errorf("%s changed: %v, want ErrExportOpen", name, err)
		}
	}
	flipped := &parsedExport{header: e.header, body: bytes.Clone(e.body)}
	flipped.body[len(flipped.body)/2] ^= 1
	if _, err := flipped.open(key); !errors.Is(err, ErrExportOpen) {
		t.Errorf("flipped bit: %v", err)
	}
	if _, err := e.open(key); err != nil {
		t.Errorf("the unchanged export: %v", err)
	}
}

// E5 (library part): a passphrase under 16 characters or over 1024 bytes
// is refused before anything is read.
func TestPassphraseBounds(t *testing.T) {
	for _, p := range []string{"", "fifteen chars..", strings.Repeat("x", 1025)} {
		if err := CheckPassphrase([]byte(p)); !errors.Is(err, ErrPassphrase) {
			t.Errorf("%d bytes: %v", len(p), err)
		}
	}
	for _, p := range []string{"sixteen chars...", "äöüäöüäöüäöüäöüä", strings.Repeat("x", 1024)} {
		if err := CheckPassphrase([]byte(p)); err != nil {
			t.Errorf("%d bytes: %v", len(p), err)
		}
	}
}

// E7: with the KEK missing and a matching keyring, restore writes the KEK
// with mode 0400, and the next bootstrap loads instead of locking.
func TestRestore(t *testing.T) {
	st, _, c, export := exported(t)
	if err := os.Remove(c.KEKFile); err != nil {
		t.Fatal(err)
	}
	_, err := Bootstrap(context.Background(), st, c)
	lockedBy(t, err, ErrKEKMissing)
	id, err := Restore(context.Background(), st, c, testPass, export)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(c.KEKFile)
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("restored KEK: %v, %v", fi, err)
	}
	res := bootstrap(t, st, c)
	if res.Created || res.Keyring.KEKID() != id {
		t.Errorf("after the restore: created %v, id %s, want %s", res.Created, res.Keyring.KEKID(), id)
	}
	if names := dirList(t, c); len(names) != 1 {
		t.Errorf("the KEK directory holds %v", names)
	}
}

// E8: restore refuses when a KEK exists (the file is unchanged), and when
// the database's keyring has another id (an export of another
// deployment).
func TestRestoreRefuses(t *testing.T) {
	st, _, c, export := exported(t)
	before := fileBytes(t, c.KEKFile)
	if _, err := Restore(context.Background(), st, c, testPass, export); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("KEK present: %v", err)
	}
	if !bytes.Equal(fileBytes(t, c.KEKFile), before) {
		t.Error("the KEK file changed")
	}
	st2, _ := newDB(t)
	c2 := testConfig(t)
	bootstrap(t, st2, c2)
	if err := os.Remove(c2.KEKFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), st2, c2, testPass, export); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("another deployment: %v", err)
	}
	if names := dirList(t, c2); len(names) != 0 {
		t.Errorf("a refused restore wrote %v", names)
	}
	st3, _ := newDB(t)
	c3 := testConfig(t)
	if _, err := Restore(context.Background(), st3, c3, testPass, export); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("empty database: %v", err)
	}
}

// E9 (C4): an export whose KEK-Id header names the database's KEK but
// whose KEK is another is refused, and nothing is written.
func TestRestoreRefusesAForgedExport(t *testing.T) {
	st, _, c, export := exported(t)
	e, err := parseExport(export)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(c.KEKFile); err != nil {
		t.Fatal(err)
	}
	real, err := openExport(t, export, testPass)
	if err != nil {
		t.Fatal(err)
	}
	forged := *real
	forged.KEK = make([]byte, KEKSize)
	if _, err := rand.Read(forged.KEK); err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sealExport(e.header, deriveKey(testPass, e.header.salt), plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), st, c, testPass, out); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("forged export: %v", err)
	}
	if names := dirList(t, c); len(names) != 0 {
		t.Errorf("a refused restore wrote %v", names)
	}
}

// E10 (C9): while another session holds the hash lock, export and
// restore fail with the lock timeout, and restore writes nothing.
func TestExportAndRestoreTakeTheHashLock(t *testing.T) {
	_, dbURL, c, export := exported(t)
	ctx := context.Background()
	short, err := store.Open(ctx, dbURL, store.WithLockTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer short.Close()
	holder := conn(t, dbURL)
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1, 0)", store.LockClassHash); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = Export(ctx, short, c, testPass, &out)
	if !errors.Is(err, store.ErrLockTimeout) || !strings.Contains(err.Error(), "hashing a password") || out.Len() != 0 {
		t.Errorf("export: %v, %d bytes written", err, out.Len())
	}
	if err := os.Remove(c.KEKFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, short, c, testPass, export); !errors.Is(err, store.ErrLockTimeout) {
		t.Errorf("restore: %v", err)
	}
	if names := dirList(t, c); len(names) != 0 {
		t.Errorf("restore wrote %v while the hash lock was held", names)
	}
}

// ST1: secrets status shows the ids and fingerprints, and none of the
// generated secret values.
func TestStatus(t *testing.T) {
	st, _ := newDB(t)
	c := testConfig(t)
	kr := bootstrap(t, st, c).Keyring
	s, err := ReadStatus(context.Background(), st, c)
	if err != nil {
		t.Fatal(err)
	}
	text := s.Text()
	for _, want := range []string{kr.KEKID().String(), hex.EncodeToString(kr.DeploymentID()), "last_export    never", "store_master   present"} {
		if !strings.Contains(text, want) {
			t.Errorf("status lacks %q:\n%s", want, text)
		}
	}
	for _, a := range pki.Anchors {
		if !strings.Contains(text, "anchor "+string(a)) {
			t.Errorf("status lacks the anchor %s", a)
		}
	}
	priv, _, err := kr.MailCrypt()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := defaultFS().load(c.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte(kr.MasterPassword()), priv, []byte(hex.EncodeToString(kek.key[:])), kek.fileContent()} {
		if strings.Contains(text, string(secret)) {
			t.Error("status shows a secret value")
		}
	}
}
