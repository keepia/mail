package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/controlgate"
	"github.com/keepia/mail/internal/gatebundle"
	"github.com/keepia/mail/internal/join"
	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/pki/pkitest"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

// newDB is a fresh migrated database: its store and its URL.
func newDB(t *testing.T) (*store.Store, string) {
	t.Helper()
	dbURL := storetest.NewUnmigrated(t)
	st, err := store.Open(context.Background(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st, dbURL
}

func conn(t *testing.T, dbURL string) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })
	return c
}

func count(t *testing.T, dbURL, table string) int {
	t.Helper()
	var n int
	if err := conn(t, dbURL).QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// testConfig is a Config with the KEK file in a new directory.
func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{KEKFile: filepath.Join(t.TempDir(), "kek")}
}

func bootstrap(t *testing.T, st *store.Store, c Config) *Result {
	t.Helper()
	res, err := Bootstrap(context.Background(), st, c)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return res
}

// lockedBy fails unless err is a *LockedError with reason, and returns
// its message.
func lockedBy(t *testing.T, err, reason error) string {
	t.Helper()
	var le *LockedError
	if !errors.As(err, &le) || !errors.Is(err, reason) {
		t.Fatalf("%v, want a LockedError for %v", err, reason)
	}
	return le.Error()
}

// dirList is the names in the KEK file's directory.
func dirList(t *testing.T, c Config) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(c.KEKFile))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// B1, B2. The first start creates the KEK (0400), the keyring and the six
// secrets; the second loads the same KEK and adds nothing.
func TestBootstrapFirstAndSecondStart(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	first := bootstrap(t, st, c)
	if !first.Created {
		t.Fatal("the first start did not create")
	}
	fi, err := os.Lstat(c.KEKFile)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o400 {
		t.Fatalf("KEK file: %v, %v", fi, err)
	}
	if got := strings.Join(dirList(t, c), " "); got != "kek" {
		t.Errorf("KEK directory holds [%s], want [kek]", got)
	}
	if n := count(t, dbURL, "secret_keyring"); n != 1 {
		t.Errorf("%d keyring rows", n)
	}
	if n := count(t, dbURL, "control_secrets"); n != 6 {
		t.Errorf("%d control_secrets rows", n)
	}
	k, err := defaultFS().load(c.KEKFile)
	if err != nil || k.id != first.Keyring.KEKID() {
		t.Fatalf("KEK file id: %v", err)
	}
	if first.Keyring.Exported() {
		t.Error("a new keyring counts as exported")
	}

	second := bootstrap(t, st, c)
	if second.Created || second.Keyring.KEKID() != first.Keyring.KEKID() {
		t.Fatalf("second start: created %v, id %s, want %s", second.Created, second.Keyring.KEKID(), first.Keyring.KEKID())
	}
	if n := count(t, dbURL, "control_secrets"); n != 6 {
		t.Errorf("after the second start: %d rows", n)
	}
	if second.Keyring.MasterPassword() != first.Keyring.MasterPassword() ||
		!bytes.Equal(second.Keyring.DeploymentID(), first.Keyring.DeploymentID()) ||
		!second.Keyring.CreatedAt().Equal(first.Keyring.CreatedAt()) {
		t.Error("the second start loaded other secrets")
	}
	for _, a := range pki.Anchors {
		if !bytes.Equal(second.Keyring.Anchor(a).Cert.Raw, first.Keyring.Anchor(a).Cert.Raw) {
			t.Errorf("anchor %s changed", a)
		}
	}
	if kr, err := Read(context.Background(), st, c); err != nil || kr.KEKID() != first.Keyring.KEKID() {
		t.Errorf("Read after the bootstrap: %v", err)
	}
}

// B3. KEK missing, secrets present: locked, and nothing is written.
func TestBootstrapKEKMissing(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	bootstrap(t, st, c)
	if err := os.Remove(c.KEKFile); err != nil {
		t.Fatal(err)
	}
	_, err := Bootstrap(context.Background(), st, c)
	lockedBy(t, err, ErrKEKMissing)
	if got := dirList(t, c); len(got) != 0 {
		t.Errorf("a locked start wrote %v", got)
	}
	if n := count(t, dbURL, "control_secrets"); n != 6 {
		t.Errorf("%d rows after a locked start", n)
	}
	_, err = Read(context.Background(), st, c)
	lockedBy(t, err, ErrKEKMissing)
}

// B4. KEK present, keyring empty: locked; the KEK file stays.
func TestBootstrapKEKWithoutSecrets(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	k := testKEK(t)
	if err := writeNew(c.KEKFile, k); err != nil {
		t.Fatal(err)
	}
	_, err := Bootstrap(context.Background(), st, c)
	le := lockedBy(t, err, ErrKEKWithoutSecrets)
	if !strings.Contains(le, "remove the volume keepia-kek") {
		t.Errorf("message: %s", le)
	}
	if n := count(t, dbURL, "secret_keyring"); n != 0 {
		t.Errorf("a locked start generated: %d keyring rows", n)
	}
	if !bytes.Equal(fileBytes(t, c.KEKFile), k.fileContent()) {
		t.Error("the KEK file changed")
	}
}

// B5. A KEK of another deployment: locked, naming both ids.
func TestBootstrapWrongKEK(t *testing.T) {
	st1, _ := newDB(t)
	st2, _ := newDB(t)
	c1, c2 := testConfig(t), testConfig(t)
	r1 := bootstrap(t, st1, c1)
	r2 := bootstrap(t, st2, c2)
	_, err := Bootstrap(context.Background(), st1, c2)
	le := lockedBy(t, err, ErrWrongKEK)
	if !strings.Contains(le, r1.Keyring.KEKID().String()) || !strings.Contains(le, r2.Keyring.KEKID().String()) {
		t.Errorf("message does not name both ids: %s", le)
	}
}

// A KEK file that fails the loader's checks locks too.
func TestBootstrapKEKFileUnusable(t *testing.T) {
	st, _ := newDB(t)
	c := testConfig(t)
	bootstrap(t, st, c)
	if err := os.Chmod(c.KEKFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Bootstrap(context.Background(), st, c)
	lockedBy(t, err, ErrKEKFile)
}

// S2 at the database: a flipped bit in a sealed row locks serve with
// ErrTampered.
func TestBootstrapTamperedRow(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	bootstrap(t, st, c)
	if _, err := conn(t, dbURL).Exec(context.Background(),
		`UPDATE control_secrets SET sealed = overlay(sealed placing decode(lpad(to_hex(get_byte(sealed, 20) # 1), 2, '0'), 'hex') from 21 for 1) WHERE name = 'mail-crypt'`); err != nil {
		t.Fatal(err)
	}
	_, err := Bootstrap(context.Background(), st, c)
	lockedBy(t, err, ErrTampered)
	// A row copied under another name does not open either (S3).
	if _, err := conn(t, dbURL).Exec(context.Background(),
		`UPDATE control_secrets SET sealed = (SELECT sealed FROM control_secrets WHERE name = 'anchor/agent') WHERE name = 'mail-crypt'`); err != nil {
		t.Fatal(err)
	}
	_, err = Bootstrap(context.Background(), st, c)
	lockedBy(t, err, ErrTampered)
}

// B6. A crash after the commit and before the link: the next start
// finishes the link with the same id.
func TestBootstrapCrashAfterCommit(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	crash := errors.New("crash after commit")
	c.afterCommit = func() error { return crash }
	if _, err := Bootstrap(context.Background(), st, c); !errors.Is(err, crash) {
		t.Fatalf("crashing bootstrap: %v", err)
	}
	if got := strings.Join(dirList(t, c), " "); got != "kek.new" {
		t.Fatalf("after the crash: [%s], want [kek.new]", got)
	}
	pending, err := defaultFS().load(c.newPath())
	if err != nil {
		t.Fatal(err)
	}
	c.afterCommit = nil
	res := bootstrap(t, st, c)
	if res.Created || res.Keyring.KEKID() != pending.id {
		t.Fatalf("next start: created %v, id %s, want %s", res.Created, res.Keyring.KEKID(), pending.id)
	}
	if got := strings.Join(dirList(t, c), " "); got != "kek" {
		t.Errorf("after the next start: [%s], want [kek]", got)
	}
	if n := count(t, dbURL, "control_secrets"); n != 6 {
		t.Errorf("%d rows", n)
	}
}

// B7. A crash before the commit: the next start removes kek.new and
// bootstraps afresh.
func TestBootstrapCrashBeforeCommit(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	crash := errors.New("crash before commit")
	c.beforeCommit = func() error { return crash }
	if _, err := Bootstrap(context.Background(), st, c); !errors.Is(err, crash) {
		t.Fatalf("crashing bootstrap: %v", err)
	}
	if n := count(t, dbURL, "secret_keyring"); n != 0 {
		t.Fatalf("the rolled-back keyring is there: %d", n)
	}
	stale, err := defaultFS().load(c.newPath())
	if err != nil {
		t.Fatal(err)
	}
	c.beforeCommit = nil
	res := bootstrap(t, st, c)
	if !res.Created || res.Keyring.KEKID() == stale.id {
		t.Fatalf("next start: created %v, id %s (stale %s)", res.Created, res.Keyring.KEKID(), stale.id)
	}
	if got := strings.Join(dirList(t, c), " "); got != "kek" {
		t.Errorf("after the next start: [%s]", got)
	}
	// A partial kek.new (a crash during its write) goes the same way.
	st2, _ := newDB(t)
	c2 := testConfig(t)
	writeFile(t, c2.newPath(), "keepia-kek-v1 abc", 0o400)
	if res := bootstrap(t, st2, c2); !res.Created {
		t.Error("a partial kek.new with an empty keyring blocked the first start")
	}
}

// B8. Two bootstraps at once, released together: one keyring, six rows,
// one KEK.
func TestBootstrapConcurrent(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*Result, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() {
			<-start
			results[i], errs[i] = Bootstrap(context.Background(), st, c)
		})
	}
	close(start)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if results[0].Created == results[1].Created || results[0].Keyring.KEKID() != results[1].Keyring.KEKID() {
		t.Errorf("created %v and %v, ids %s and %s", results[0].Created, results[1].Created, results[0].Keyring.KEKID(), results[1].Keyring.KEKID())
	}
	if n := count(t, dbURL, "secret_keyring"); n != 1 {
		t.Errorf("%d keyring rows", n)
	}
	if n := count(t, dbURL, "control_secrets"); n != 6 {
		t.Errorf("%d rows", n)
	}
}

// B9, B13. The bootstrap lock spans the link: a command's read between the
// commit and the link fails with the lock timeout; afterwards, with the
// link still missing (a crash), it reports "bootstrap in progress", not
// "KEK missing", and writes nothing.
func TestBootstrapLockSpansTheLink(t *testing.T) {
	st, _ := newDB(t)
	c := testConfig(t)
	inWindow, release := make(chan struct{}), make(chan struct{})
	crash := errors.New("crash after commit")
	c.afterCommit = func() error {
		close(inWindow)
		<-release
		return crash
	}
	done := make(chan error, 1)
	go func() {
		_, err := Bootstrap(context.Background(), st, c)
		done <- err
	}()
	select {
	case <-inWindow:
	case err := <-done:
		t.Fatalf("bootstrap returned before the window: %v", err)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("bootstrap did not reach the window")
	}
	rc := Config{KEKFile: c.KEKFile, LockTimeout: 50 * time.Millisecond}
	_, err := Read(context.Background(), st, rc)
	close(release)
	if !errors.Is(err, store.ErrLockTimeout) {
		t.Fatalf("read inside the window: %v, want the lock timeout", err)
	}
	if err := <-done; !errors.Is(err, crash) {
		t.Fatalf("bootstrap: %v", err)
	}
	_, err = Read(context.Background(), st, rc)
	lockedBy(t, err, ErrBootstrapInProgress)
	if got := strings.Join(dirList(t, c), " "); got != "kek.new" {
		t.Errorf("a read changed the directory: [%s]", got)
	}
	// An empty deployment: "not initialized".
	st2, _ := newDB(t)
	_, err = Read(context.Background(), st2, testConfig(t))
	lockedBy(t, err, ErrNotInitialized)
}

// B11. A kek.new identical to the KEK is removed, and the keyring loads.
func TestBootstrapKEKNewSameAsKEK(t *testing.T) {
	st, _ := newDB(t)
	c := testConfig(t)
	first := bootstrap(t, st, c)
	if err := os.Link(c.KEKFile, c.newPath()); err != nil {
		t.Fatal(err)
	}
	res := bootstrap(t, st, c)
	if res.Keyring.KEKID() != first.Keyring.KEKID() {
		t.Fatal("other id")
	}
	if got := strings.Join(dirList(t, c), " "); got != "kek" {
		t.Errorf("after the start: [%s], want [kek]", got)
	}
}

// B12, B14, B15. A kek.new that is neither the keyring's nor the KEK's is
// kept, and serve is locked.
func TestBootstrapStrayKEKNewIsKept(t *testing.T) {
	stray := testKEK(t)
	t.Run("B12 no kek, kek.new of another KEK", func(t *testing.T) {
		st, _ := newDB(t)
		c := testConfig(t)
		bootstrap(t, st, c)
		if err := os.Remove(c.KEKFile); err != nil {
			t.Fatal(err)
		}
		if err := writeNew(c.newPath(), stray); err != nil {
			t.Fatal(err)
		}
		_, err := Bootstrap(context.Background(), st, c)
		lockedBy(t, err, ErrStrayKEKNew)
		if !bytes.Equal(fileBytes(t, c.newPath()), stray.fileContent()) {
			t.Error("kek.new changed")
		}
		if got := strings.Join(dirList(t, c), " "); got != "kek.new" {
			t.Errorf("directory [%s]", got)
		}
	})
	t.Run("B12 no kek, unreadable kek.new", func(t *testing.T) {
		st, _ := newDB(t)
		c := testConfig(t)
		bootstrap(t, st, c)
		if err := os.Remove(c.KEKFile); err != nil {
			t.Fatal(err)
		}
		writeFile(t, c.newPath(), "keepia-kek-v1 partial", 0o400)
		_, err := Bootstrap(context.Background(), st, c)
		lockedBy(t, err, ErrStrayKEKNew)
		if string(fileBytes(t, c.newPath())) != "keepia-kek-v1 partial" {
			t.Error("kek.new changed")
		}
	})
	t.Run("B14 kek of the keyring, kek.new of another KEK", func(t *testing.T) {
		st, _ := newDB(t)
		c := testConfig(t)
		bootstrap(t, st, c)
		if err := writeNew(c.newPath(), stray); err != nil {
			t.Fatal(err)
		}
		_, err := Bootstrap(context.Background(), st, c)
		lockedBy(t, err, ErrStrayKEKNew)
		if !bytes.Equal(fileBytes(t, c.newPath()), stray.fileContent()) {
			t.Error("kek.new changed")
		}
	})
	t.Run("B15 kek and kek.new, keyring empty", func(t *testing.T) {
		st, _ := newDB(t)
		c := testConfig(t)
		if err := writeNew(c.KEKFile, testKEK(t)); err != nil {
			t.Fatal(err)
		}
		if err := writeNew(c.newPath(), stray); err != nil {
			t.Fatal(err)
		}
		_, err := Bootstrap(context.Background(), st, c)
		lockedBy(t, err, ErrKEKWithoutSecrets)
		if !bytes.Equal(fileBytes(t, c.newPath()), stray.fileContent()) {
			t.Error("kek.new changed")
		}
	})
}

// G1 (as stored), G2, G3. The generated secrets: four anchors, the
// mail_crypt pair in Dovecot's PEM forms, and a 43-character master
// password that differs between deployments.
func TestGeneratedSecrets(t *testing.T) {
	st, _ := newDB(t)
	st2, _ := newDB(t)
	a := bootstrap(t, st, testConfig(t)).Keyring
	b := bootstrap(t, st2, testConfig(t)).Keyring

	for _, name := range pki.Anchors {
		an := a.Anchor(name)
		if an == nil || !an.Cert.IsCA || !an.Cert.MaxPathLenZero ||
			an.Cert.Subject.Organization[0] != hex.EncodeToString(a.DeploymentID()) {
			t.Errorf("anchor %s: %+v", name, an)
		}
	}
	priv, pub, err := a.MailCrypt()
	if err != nil {
		t.Fatal(err)
	}
	pb, rest := pem.Decode(priv)
	if pb == nil || pb.Type != "PRIVATE KEY" || len(rest) != 0 || len(pb.Headers) != 0 {
		t.Fatalf("private PEM: %v", pb)
	}
	k, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	key, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		t.Fatalf("private key: %T, %v", k, err)
	}
	ub, _ := pem.Decode(pub)
	if ub == nil || ub.Type != "PUBLIC KEY" {
		t.Fatalf("public PEM: %v", ub)
	}
	pk, err := x509.ParsePKIXPublicKey(ub.Bytes)
	if err != nil || !key.PublicKey.Equal(pk) {
		t.Fatalf("the public key does not match the private one: %v", err)
	}

	pw := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	if !pw.MatchString(a.MasterPassword()) || !pw.MatchString(b.MasterPassword()) {
		t.Errorf("master passwords of %d and %d characters", len(a.MasterPassword()), len(b.MasterPassword()))
	}
	if a.MasterPassword() == b.MasterPassword() || bytes.Equal(a.DeploymentID(), b.DeploymentID()) {
		t.Error("two deployments share a password or deployment id")
	}
}

// B10 (with #96 part 2's N7). A database dump reveals no secret: no
// column of secret_keyring, control_secrets, certificates, anchor_crls
// and join_tokens, read as text and as raw bytes, contains the KEK, a
// private key (DER, its hex and base64, PEM, or the bare scalar; the
// control gate's included), the master password, or a join token or its
// secret.
func TestDumpRevealsNoSecret(t *testing.T) {
	st, dbURL := newDB(t)
	c := testConfig(t)
	kr := bootstrap(t, st, c).Keyring
	kek, err := defaultFS().load(c.KEKFile)
	if err != nil {
		t.Fatal(err)
	}

	var needles [][]byte
	add := func(b []byte) {
		needles = append(needles, b, []byte(hex.EncodeToString(b)),
			[]byte(base64.StdEncoding.EncodeToString(b)), []byte(base64.RawURLEncoding.EncodeToString(b)))
	}
	add(kek.key[:])
	needles = append(needles, kek.fileContent())
	needles = append(needles, []byte(kr.MasterPassword()))
	add([]byte(kr.MasterPassword()))
	keys := []*ecdsa.PrivateKey{kr.m.mailCrypt}
	for _, a := range pki.Anchors {
		keys = append(keys, kr.Anchor(a).Signer.(*ecdsa.PrivateKey))
	}
	for _, k := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		add(der)
		ec, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		add(ec)
		scalar, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		add(scalar)
	}
	privPEM, _, err := kr.MailCrypt()
	if err != nil {
		t.Fatal(err)
	}
	needles = append(needles, privPEM)

	// #96 part 2 (N7): the lists, the control gate's certificate (its key
	// stays in the bundle), two tokens, an agent certificate and a
	// removal.
	ctx := context.Background()
	w := &controlgate.Writer{Store: st, Anchors: kr, Dir: t.TempDir()}
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	gb, err := gatebundle.Read(w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	keys = append(keys, gb.Key.(*ecdsa.PrivateKey))
	service := kr.Anchor(pki.AnchorService).Cert
	var tokens []join.Token
	for _, name := range []string{"s1", "s2"} {
		tok, err := join.AddServer(ctx, st, service, name, []string{"store"}, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
		add(tok.Secret[:])
		needles = append(needles, []byte(tok.String()), []byte(tok.String()[len(join.TokenPrefix):]))
	}
	csr, _ := pkitest.CSR(t)
	if _, err := join.Redeem(ctx, st, kr, tokens[1], csr, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.RevokeServer(ctx, st, kr, "s1", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys[len(keys)-1:] {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		add(der)
		ec, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		add(ec)
		scalar, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		add(scalar)
		needles = append(needles, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}

	db := conn(t, dbURL)
	var haystacks [][]byte
	for _, q := range []string{
		`SELECT t::text FROM secret_keyring t`,
		`SELECT t::text FROM control_secrets t`,
		`SELECT t::text FROM certificates t`,
		`SELECT t::text FROM anchor_crls t`,
		`SELECT t::text FROM join_tokens t`,
	} {
		rows, err := db.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		texts, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range texts {
			haystacks = append(haystacks, []byte(s), []byte(strings.ToLower(s)))
		}
	}
	// Every column as raw bytes (bytea as is, the others as text).
	for _, q := range []string{
		`SELECT kek_id, deployment_id, convert_to(created_at::text, 'UTF8'), convert_to(coalesce(last_export_at::text, ''), 'UTF8') FROM secret_keyring`,
		`SELECT convert_to(name, 'UTF8'), int4send(version), coalesce(public, ''::bytea), kek_id, sealed FROM control_secrets`,
		`SELECT serial, convert_to(anchor, 'UTF8'), convert_to(coalesce(server_id::text, ''), 'UTF8'), convert_to(purpose, 'UTF8'),
			convert_to(coalesce(dns_name, ''), 'UTF8'), spki_sha256, convert_to(not_before::text || not_after::text, 'UTF8'), der,
			convert_to(coalesce(revoked_at::text, '') || coalesce(revocation_reason::text, ''), 'UTF8') FROM certificates`,
		`SELECT convert_to(anchor, 'UTF8'), int8send(number), convert_to(this_update::text || next_update::text, 'UTF8'), der FROM anchor_crls`,
		`SELECT id, convert_to(server_id::text, 'UTF8'), secret_sha256, convert_to(created_at::text || expires_at::text
			|| coalesce(used_at::text, '') || coalesce(invalidated_at::text, ''), 'UTF8') FROM join_tokens`,
	} {
		rows, err := db.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				haystacks = append(haystacks, v.([]byte))
			}
		}
		if rows.Err() != nil {
			t.Fatal(rows.Err())
		}
	}
	if count(t, dbURL, "certificates") < 2 || count(t, dbURL, "anchor_crls") != 4 || count(t, dbURL, "join_tokens") != 2 {
		t.Fatal("the part 2 tables are not filled")
	}
	// Text and lowercase text of 1+6+2+4+2 rows, and every column raw.
	if len(haystacks) < 2*(1+6+2+4+2)+4+6*5+2*9+4*4+2*4 {
		t.Fatalf("read only %d values", len(haystacks))
	}
	for _, h := range haystacks {
		for _, n := range needles {
			if bytes.Contains(h, n) || bytes.Contains(h, bytes.ToLower(n)) {
				t.Fatalf("the dump contains a secret (%d bytes of %q...)", len(n), h[:min(len(h), 24)])
			}
		}
	}
}
