package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/password"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

// Placeholders of the CLI tests: never a real password or a real user's
// hash. The hashes come from `doveadm pw` in the pinned Dovecot image
// (internal/password's tests name them).
const (
	cliPassword  = "placeholder-pass-1"
	cliPassword2 = "placeholder-pass-2"
	hashArgon    = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$VXHwODjENRPzvF5vKaDyyw$JlomXtSbd0QKwrSlsr81wRpwP8OSnlVfK6mNNLzGxmw"
	hashSSHA512  = "{SSHA512}RvNkIaXOwVdz0c7Qbi6EtCT+x6IFQilBIJNYsR9N4Ety2hrSWElOmqw7aubUA6HJNJjAu54BoOPcOt/C+5YmTnh9QF0="
)

// markerHash is a valid {SSHA512} hash whose text is unmistakable, for the
// checks that no output quotes a hash (#111, carried condition 1).
var markerHash = "{SSHA512}" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("keepia-marker-hash-", 5)))

// fakeTerminal is the terminal seam: tty says whether stdin is a
// terminal, and each ReadPassword returns the next entry.
type fakeTerminal struct {
	tty     bool
	entries []string
	reads   int
}

func (f *fakeTerminal) IsTerminal() bool { return f.tty }

func (f *fakeTerminal) ReadPassword() ([]byte, error) {
	if f.reads >= len(f.entries) {
		return nil, errors.New("fake terminal: no more entries")
	}
	f.reads++
	return []byte(f.entries[f.reads-1]), nil
}

// noTTY is a standard input that is not a terminal.
func noTTY() *fakeTerminal { return &fakeTerminal{} }

// cliDB is a migrated test database for the CLI tests, with
// KEEPIA_DATABASE_URL set to it, a store for the setup that the CLI does
// not offer (servers, stores), and every output of the test's runs, which
// the cleanup checks for passwords and hashes.
type cliDB struct {
	url     string
	st      *store.Store
	conn    *pgx.Conn
	opts    []store.Option
	mu      sync.Mutex
	outputs []string
	// secrets are further passwords and hashes that no output may
	// contain, such as the refused inputs of test 10.
	secrets []string
}

// addSecret adds s to the texts that no output may contain.
func (c *cliDB) addSecret(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.secrets = append(c.secrets, s)
}

func newCLIDB(t *testing.T) *cliDB {
	t.Helper()
	ctx := context.Background()
	c := &cliDB{url: storetest.NewUnmigrated(t)}
	t.Setenv(config.EnvDatabaseURL, c.url)
	st, err := store.Open(ctx, c.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	c.st = st
	conn, err := pgx.Connect(ctx, c.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	c.conn = conn
	// Registered last, so it runs first: no output of any run contains a
	// test password, a placeholder hash or a hash stored in the database.
	t.Cleanup(func() { c.checkOutputs(t) })
	return c
}

// checkOutputs fails the test if any output contains a password or a
// hash (test 10: across all CLI tests).
func (c *cliDB) checkOutputs(t *testing.T) {
	t.Helper()
	secrets := []string{cliPassword, cliPassword2, hashArgon, hashSSHA512, markerHash, "keepia-marker-hash"}
	rows, err := c.conn.Query(context.Background(), "SELECT password_hash FROM mailboxes")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	secrets = append(secrets, stored...)
	c.mu.Lock()
	defer c.mu.Unlock()
	secrets = append(secrets, c.secrets...)
	// The start of every field of a hash on its own as well (a salt, a
	// tag, an SSHA body): PostgreSQL's DETAIL cuts a long value short.
	for _, h := range secrets {
		if !strings.HasPrefix(h, "{") {
			continue
		}
		_, body, _ := strings.Cut(h, "}")
		for f := range strings.SplitSeq(body, "$") {
			if len(f) >= 16 && !strings.HasPrefix(f, "m=") && !strings.HasPrefix(f, "rounds=") {
				secrets = append(secrets, f[:16])
			}
		}
	}
	for _, out := range c.outputs {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("an output contains a password or a hash (%.12q...):\n%s", s, out)
			}
		}
	}
}

// run runs keepia-mail with args, stdin and the terminal tty, and returns
// its exit code, stdout, stderr and the error message main would print.
func (c *cliDB) run(t *testing.T, stdin string, tty terminal, args ...string) (code int, stdout, stderr, msg string) {
	t.Helper()
	if tty == nil {
		tty = noTTY()
	}
	stdout, stderr, err := execute(context.Background(), options{
		stdin: strings.NewReader(stdin), terminal: tty, storeOptions: c.opts,
	}, args...)
	code, msg = exitStatus(err)
	c.mu.Lock()
	c.outputs = append(c.outputs, stdout+"\n"+stderr+"\n"+msg)
	c.mu.Unlock()
	return code, stdout, stderr, msg
}

// ok runs args and wants exit 0 and exactly want on stdout.
func (c *cliDB) ok(t *testing.T, want, stdin string, args ...string) {
	t.Helper()
	code, out, errOut, msg := c.run(t, stdin, nil, args...)
	if code != 0 || out != want {
		t.Errorf("%v: exit %d, stdout:\n%s\nstderr: %s\nerror: %s\nwant exit 0 and:\n%s", args, code, out, errOut, msg, want)
	}
}

// fail runs args and wants the exit code and an error message that
// contains part, and nothing on stdout.
func (c *cliDB) fail(t *testing.T, code int, part, stdin string, args ...string) {
	t.Helper()
	got, out, _, msg := c.run(t, stdin, nil, args...)
	if got != code || !strings.Contains(msg, part) || out != "" {
		t.Errorf("%v: exit %d, error %q, stdout %q; want exit %d and an error with %q", args, got, msg, out, code, part)
	}
}

// addStores adds the server srv1 (store) and the active stores gates.
func (c *cliDB) addStores(t *testing.T, gates ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := c.st.CreateServer(ctx, "srv1", []string{"store"}); err != nil {
		t.Fatal(err)
	}
	for i, g := range gates {
		if _, err := c.st.CreateStore(ctx, store.NewStore{
			Server: "srv1", GateName: g, GateIPv4: netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), EgressPort: int32(2001 + i), //nolint:gosec // a few stores
		}); err != nil {
			t.Fatal(err)
		}
		if err := c.st.SetStoreState(ctx, g, store.StoreActive); err != nil {
			t.Fatal(err)
		}
	}
}

// seedCLI adds, through the CLI, the groups acme and other, the domains
// example.org and example.net (acme) and example.com (other), the alias
// domain example.info, and through the store API the stores store-a and
// store-b. Each success output is checked verbatim.
func seedCLI(t *testing.T, c *cliDB) {
	t.Helper()
	c.ok(t, "group acme added\n", "", "group", "add", "acme")
	c.ok(t, "group other added\n", "", "group", "add", "Other")
	c.ok(t, "domain example.org added to group acme\n", "", "domain", "add", "Example.ORG", "--group", "acme")
	c.ok(t, "domain example.net added to group acme\n", "", "domain", "add", "example.net", "--group", "acme")
	c.ok(t, "domain example.com added to group other\n", "", "domain", "add", "example.com", "--group", "other")
	c.ok(t, "alias domain example.info added for example.org\n", "", "alias-domain", "add", "example.info", "--domain", "example.org")
	c.addStores(t, "store-a", "store-b")
}

// Test 12: every command's success output, verbatim, with the list
// filters, a catch-all, and the placement the mailbox adds report.
func TestCLICommands(t *testing.T) {
	c := newCLIDB(t)
	seedCLI(t, c)

	c.ok(t, "GROUP  DOMAINS\nacme   2\nother  1\n", "", "group", "list")
	c.ok(t, "DOMAIN       GROUP  ACTIVE\nexample.com  other  true\nexample.net  acme   true\nexample.org  acme   true\n", "", "domain", "list")
	c.ok(t, "DOMAIN       GROUP  ACTIVE\nexample.com  other  true\n", "", "domain", "list", "--group", "other")
	c.ok(t, "domain example.net updated\n", "", "domain", "set", "example.net", "--active=false")
	c.ok(t, "DOMAIN       GROUP  ACTIVE\nexample.net  acme   false\nexample.org  acme   true\n", "", "domain", "list", "--group", "acme")

	c.ok(t, "alias domain example.biz added for example.org\n", "", "alias-domain", "add", "example.biz", "--domain", "example.org")
	c.ok(t, "alias domain example.biz updated\n", "", "alias-domain", "set", "example.biz", "--domain", "example.net", "--active=false")
	c.ok(t, "ALIAS DOMAIN  DOMAIN       GROUP  ACTIVE\nexample.biz   example.net  acme   false\nexample.info  example.org  acme   true\n", "", "alias-domain", "list")
	c.ok(t, "ALIAS DOMAIN  DOMAIN       GROUP  ACTIVE\nexample.info  example.org  acme   true\n", "", "alias-domain", "list", "--domain", "example.org")
	c.ok(t, "ALIAS DOMAIN  DOMAIN  GROUP  ACTIVE\n", "", "alias-domain", "list", "--group", "other")

	// Placement: both stores are empty, so the gate name decides; then
	// store-a holds 5 GiB and store-b gets the next one.
	c.ok(t, "mailbox alice@example.org added on store store-a\n", hashArgon, "mailbox", "add", "alice@example.org", "--quota", "5GiB", "--password-hash-stdin")
	c.ok(t, "mailbox bob@example.org added on store store-b\n", hashSSHA512+"\n", "mailbox", "add", "Bob@example.org", "--quota", "1536MiB", "--pop3=false", "--password-hash-stdin")
	c.ok(t, "mailbox carol@example.com added on store store-a\n", hashSSHA512, "mailbox", "add", "carol@example.com", "--quota", "unlimited", "--store", "store-a", "--password-hash-stdin")
	c.ok(t, "mailbox dave@example.org added on store store-b\n", hashSSHA512, "mailbox", "add", "dave@example.org", "--quota", "1000", "--password-hash-stdin")
	c.ok(t, ""+
		"ADDRESS            GROUP  STORE    QUOTA      IMAP  POP3   SMTP  STATE   SCHEME\n"+
		"carol@example.com  other  store-a  unlimited  true  true   true  active  SSHA512\n"+
		"alice@example.org  acme   store-a  5GiB       true  true   true  active  ARGON2ID\n"+
		"bob@example.org    acme   store-b  1536MiB    true  false  true  active  SSHA512\n"+
		"dave@example.org   acme   store-b  1000       true  true   true  active  SSHA512\n", "", "mailbox", "list")
	c.ok(t, "mailbox bob@example.org updated\n", "", "mailbox", "set", "bob@example.org", "--quota", "2GiB", "--imap=false", "--state", "disabled")
	c.ok(t, ""+
		"ADDRESS           GROUP  STORE    QUOTA  IMAP   POP3   SMTP  STATE     SCHEME\n"+
		"bob@example.org   acme   store-b  2GiB   false  false  true  disabled  SSHA512\n"+
		"dave@example.org  acme   store-b  1000   true   true   true  active    SSHA512\n", "", "mailbox", "list", "--store", "store-b")
	c.ok(t, ""+
		"ADDRESS            GROUP  STORE    QUOTA      IMAP  POP3  SMTP  STATE   SCHEME\n"+
		"carol@example.com  other  store-a  unlimited  true  true  true  active  SSHA512\n", "", "mailbox", "list", "--group", "other")
	c.ok(t, "ADDRESS  GROUP  STORE  QUOTA  IMAP  POP3  SMTP  STATE  SCHEME\n", "", "mailbox", "list", "--domain", "example.net")

	c.ok(t, "alias sales@example.org added (2 targets)\n", "", "alias", "add", "sales@example.org", "--target", "dave@example.org", "--target", "alice@example.org")
	c.ok(t, "alias @example.org added (1 targets)\n", "", "alias", "add", "@example.org", "--target", "alice@example.org")
	c.ok(t, "alias sales@example.org updated\n", "", "alias", "set", "sales@example.org", "--add-target", "bob@example.org", "--remove-target", "dave@example.org")
	c.ok(t, "alias @example.org updated\n", "", "alias", "set", "@example.org", "--active=false")
	c.ok(t, "ALIAS              TARGETS                            ACTIVE\n"+
		"@example.org       alice@example.org                  false\n"+
		"sales@example.org  alice@example.org,bob@example.org  true\n", "", "alias", "list")
	c.ok(t, "ALIAS  TARGETS  ACTIVE\n", "", "alias", "list", "--group", "other")

	c.ok(t, "alice@example.org may send as @example.net\n", "", "send-as", "add", "alice@example.org", "@example.net")
	c.ok(t, "alice@example.org may send as sales@example.org\n", "", "send-as", "add", "alice@example.org", "sales@example.org")
	c.ok(t, "send-as alice@example.org @example.net updated\n", "", "send-as", "set", "alice@example.org", "@example.net", "--active=false")
	c.ok(t, "MAILBOX            SEND AS            ACTIVE\n"+
		"alice@example.org  @example.net       false\n"+
		"alice@example.org  sales@example.org  true\n", "", "send-as", "list", "--mailbox", "alice@example.org")
	c.ok(t, "MAILBOX  SEND AS  ACTIVE\n", "", "send-as", "list", "--group", "other")

	c.ok(t, "group customers updated\n", "", "group", "set", "acme", "--name", "customers")
	c.ok(t, "GROUP      DOMAINS\ncustomers  2\nother      1\n", "", "group", "list")
}

// Test 12: each exit-code class at least once. 64: usage, checked before
// the database is contacted (here even without a database URL); 3: the
// row already exists; 1: not found, and refused by a rule (T3, T4, T6).
func TestCLIExitCodes(t *testing.T) {
	c := newCLIDB(t)
	seedCLI(t, c)
	c.ok(t, "mailbox alice@example.org added on store store-a\n", hashArgon, "mailbox", "add", "alice@example.org", "--quota", "1GiB", "--password-hash-stdin")
	c.ok(t, "mailbox bob@example.com added on store store-b\n", hashArgon, "mailbox", "add", "bob@example.com", "--quota", "1GiB", "--password-hash-stdin")
	c.ok(t, "alias solo@example.org added (1 targets)\n", "", "alias", "add", "solo@example.org", "--target", "alice@example.org")

	usage := []struct {
		part string
		args []string
	}{
		{`unknown command "delete" for "keepia-mail mailbox"`, []string{"mailbox", "delete", "alice@example.org"}},
		{"unknown flag: --store", []string{"mailbox", "set", "alice@example.org", "--store", "store-b"}},
		{"unknown flag: --password", []string{"mailbox", "add", "carol@example.org", "--quota", "1GiB", "--password", cliPassword}},
		{"unknown flag: --password", []string{"mailbox", "set", "alice@example.org", "--password=" + cliPassword}},
		{`unknown command "frobnicate" for "keepia-mail"`, []string{"frobnicate"}},
		{"keepia-mail group needs a subcommand", []string{"group"}},
		{"accepts 1 arg(s), received 2", []string{"group", "add", "a", "b"}},
		{"accepts 1 arg(s), received 0", []string{"domain", "set"}},
		{`unknown command "x" for "keepia-mail migrate"`, []string{"migrate", "x"}},
		{"invalid argument", []string{"domain", "set", "example.org", "--active=maybe"}},
		{`invalid group name "a_b"`, []string{"group", "add", "a_b"}},
		{`invalid domain "192.0.2.1"`, []string{"domain", "add", "192.0.2.1", "--group", "acme"}},
		{`invalid domain "-x.example.org"`, []string{"domain", "add", "--group", "acme", "--", "-x.example.org"}},
		{`invalid domain "kKelvin.example.org"`, []string{"domain", "add", "kKelvin.example.org", "--group", "acme"}},
		{"domain add needs --group", []string{"domain", "add", "example.biz"}},
		{`invalid address "a+b@example.org"`, []string{"mailbox", "add", "a+b@example.org", "--quota", "1GiB", "--password-hash-stdin"}},
		{`invalid address "a*b@example.org"`, []string{"alias", "add", "a*b@example.org", "--target", "alice@example.org"}},
		{`invalid address "a..b@example.org"`, []string{"alias", "add", "solo2@example.org", "--target", "a..b@example.org"}},
		{`invalid address "@example.org"`, []string{"mailbox", "add", "@example.org", "--quota", "1GiB", "--password-hash-stdin"}},
		{"longer than 254 characters", []string{"alias", "add", strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63), "--target", "alice@example.org"}},
		{"mailbox add needs --quota", []string{"mailbox", "add", "carol@example.org", "--password-hash-stdin"}},
		{`invalid quota "-1"`, []string{"mailbox", "set", "alice@example.org", "--quota", "-1"}},
		{`invalid quota "5GB"`, []string{"mailbox", "set", "alice@example.org", "--quota", "5GB"}},
		{`invalid quota "8388608TiB"`, []string{"mailbox", "set", "alice@example.org", "--quota", "8388608TiB"}},
		{`invalid quota "9223372036854775808"`, []string{"mailbox", "set", "alice@example.org", "--quota", "9223372036854775808"}},
		{`invalid state "deleted"`, []string{"mailbox", "set", "alice@example.org", "--state", "deleted"}},
		{"needs at least one of", []string{"mailbox", "set", "alice@example.org"}},
		{"needs at least one of", []string{"mailbox", "set", "alice@example.org", "--password-stdin=false"}},
		{"needs at least one of --name", []string{"group", "set", "acme"}},
		{"needs at least one of --active", []string{"domain", "set", "example.org"}},
		{"needs at least one of --domain, --active", []string{"alias-domain", "set", "example.info"}},
		{"needs at least one of --add-target", []string{"alias", "set", "solo@example.org"}},
		{"needs at least one of --active", []string{"send-as", "set", "alice@example.org", "@example.net"}},
		{"alias add needs at least one --target", []string{"alias", "add", "x@example.org"}},
		{"accepts 2 arg(s), received 1", []string{"send-as", "add", "alice@example.org"}},
	}
	for _, u := range usage {
		c.fail(t, exitUsage, u.part, hashArgon, u.args...)
	}
	// Usage errors need no database: they are found before it is
	// contacted.
	t.Setenv(config.EnvDatabaseURL, "")
	for _, u := range usage[:4] {
		c.fail(t, exitUsage, u.part, hashArgon, u.args...)
	}
	c.fail(t, exitFailed, config.EnvDatabaseURL, "", "group", "list")
	t.Setenv(config.EnvDatabaseURL, c.url)

	c.fail(t, exitExists, "rule customer_groups_name_key", "", "group", "add", "acme")
	c.fail(t, exitExists, "rule domain_name_taken", "", "domain", "add", "example.info", "--group", "acme")
	c.fail(t, exitExists, "rule address_taken", "", "alias", "add", "alice@example.org", "--target", "alice@example.org")
	c.fail(t, exitExists, "rule address_taken", hashArgon, "mailbox", "add", "solo@example.org", "--quota", "1GiB", "--password-hash-stdin")
	c.fail(t, exitExists, "rule mailboxes_address_key", hashArgon, "mailbox", "add", "alice@example.org", "--quota", "1GiB", "--password-hash-stdin")

	c.fail(t, exitFailed, "group nobody: not found", "", "domain", "add", "example.biz", "--group", "nobody")
	c.fail(t, exitFailed, "mailbox nobody@example.org: not found", "", "mailbox", "set", "nobody@example.org", "--quota", "1GiB")
	c.fail(t, exitFailed, "domain example.biz: not found", hashArgon, "mailbox", "add", "x@example.biz", "--quota", "1GiB", "--password-hash-stdin")
	c.fail(t, exitFailed, "example.info is an alias domain of example.org", hashArgon, "mailbox", "add", "x@example.info", "--quota", "1GiB", "--password-hash-stdin")
	c.fail(t, exitFailed, "store store-c: not found", hashArgon, "mailbox", "add", "x@example.org", "--quota", "1GiB", "--store", "store-c", "--password-hash-stdin")
	c.fail(t, exitFailed, "mailbox nobody@example.org: not found", "", "alias", "add", "x@example.org", "--target", "nobody@example.org")
	c.fail(t, exitFailed, "give the mailbox address alice@example.org", "", "alias", "add", "x@example.org", "--target", "alice@example.info")
	// The rules: T3 (send-as across groups), T4 (an alias target across
	// groups, also for a catch-all), T6 (removing the last target).
	c.fail(t, exitFailed, "rule send_as_group", "", "send-as", "add", "alice@example.org", "@example.com")
	c.fail(t, exitFailed, "rule alias_target_group", "", "alias", "add", "x@example.org", "--target", "bob@example.com")
	c.fail(t, exitFailed, "rule alias_target_group", "", "alias", "add", "@example.org", "--target", "bob@example.com")
	c.fail(t, exitFailed, "rule alias_without_target", "", "alias", "set", "solo@example.org", "--remove-target", "alice@example.org")
	c.fail(t, exitFailed, "rule alias_domain_group", "", "alias-domain", "set", "example.info", "--domain", "example.com")
	c.ok(t, "ALIAS             TARGETS            ACTIVE\nsolo@example.org  alice@example.org  true\n", "", "alias", "list")
}

// cliAdd runs mailbox add of local@example.org (1 GiB) with the given
// stdin, terminal and password flags.
func cliAdd(c *cliDB, t *testing.T, local, stdin string, tty terminal, flags ...string) (int, string, string, string) {
	t.Helper()
	return c.run(t, stdin, tty, append([]string{"mailbox", "add", local + "@example.org", "--quota", "1GiB"}, flags...)...)
}

// storedHash is the stored hash of local@example.org.
func (c *cliDB) storedHash(t *testing.T, local string) string {
	t.Helper()
	var h string
	if err := c.conn.QueryRow(context.Background(), `
		SELECT m.password_hash FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		WHERE d.name = 'example.org' AND m.local_part = $1`, local).Scan(&h); err != nil {
		t.Fatalf("%s: %v", local, err)
	}
	return h
}

// wantPassword checks that local@example.org's stored hash is a new
// Argon2id hash of pw.
func (c *cliDB) wantPassword(t *testing.T, local, pw string) {
	t.Helper()
	h := c.storedHash(t, local)
	if newHashFormat := strings.HasPrefix(h, "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$") && len(h) == 107; !newHashFormat {
		t.Errorf("%s: stored %.40q..., want a new Argon2id hash", local, h)
	}
	if !argonMatches(t, h, pw) {
		t.Errorf("%s: the stored hash is not of the expected password", local)
	}
}

// argonMatches tells whether the {ARGON2ID} hash h is of pw.
func argonMatches(t *testing.T, h, pw string) bool {
	t.Helper()
	a, err := password.ParseArgon2ID(h)
	if err != nil {
		t.Fatal(err)
	}
	enc := password.EncodeArgon2ID(password.Argon2ID{
		Memory: a.Memory, Time: a.Time, Threads: a.Threads, Salt: a.Salt,
		Key: argonKey(pw, a),
	})
	return enc == h
}

// argonKey recomputes the tag of a for pw.
func argonKey(pw string, a password.Argon2ID) []byte {
	return argon2.IDKey([]byte(pw), a.Salt, a.Time, a.Memory, a.Threads, uint32(len(a.Key))) //nolint:gosec // at most 64
}

// Test 10: the password input. A password never comes from argv; it is
// read from stdin (one trailing newline or CRLF stripped) or prompted for
// twice without echo on a terminal, checked against the rule (12 to 256
// characters, no control characters, valid UTF-8), and every refusal is a
// usage error (exit 64). No output contains a password or a hash
// (checkOutputs, for every CLI test).
func TestCLIPasswordInput(t *testing.T) {
	c := newCLIDB(t)
	seedCLI(t, c)

	// Accepted: stdin with "\n" and with "\r\n", and the prompt.
	if code, _, _, msg := cliAdd(c, t, "lf", cliPassword+"\n", nil, "--password-stdin"); code != 0 {
		t.Fatalf("--password-stdin with \\n: exit %d: %s", code, msg)
	}
	c.wantPassword(t, "lf", cliPassword)
	if code, _, _, msg := c.run(t, cliPassword2+"\r\n", nil, "mailbox", "set", "lf@example.org", "--password-stdin"); code != 0 {
		t.Fatalf("set --password-stdin with \\r\\n: exit %d: %s", code, msg)
	}
	c.wantPassword(t, "lf", cliPassword2)
	tty := &fakeTerminal{tty: true, entries: []string{cliPassword, cliPassword}}
	code, out, errOut, msg := cliAdd(c, t, "prompted", "", tty)
	// lf took store-a, so placement gives store-b.
	if code != 0 || out != "mailbox prompted@example.org added on store store-b\n" || tty.reads != 2 ||
		errOut != "Password: \nRepeat the password: \n" {
		t.Fatalf("the prompt: exit %d, %d reads, stdout %q, stderr %q: %s", code, tty.reads, out, errOut, msg)
	}
	c.wantPassword(t, "prompted", cliPassword)
	// --password-stdin on a terminal prompts instead of reading stdin.
	tty = &fakeTerminal{tty: true, entries: []string{cliPassword2, cliPassword2}}
	if code, _, _, msg := cliAdd(c, t, "prompted2", "not-the-password\n", tty, "--password-stdin"); code != 0 || tty.reads != 2 {
		t.Fatalf("--password-stdin on a terminal: exit %d, %d reads: %s", code, tty.reads, msg)
	}
	c.wantPassword(t, "prompted2", cliPassword2)
	// An imported hash is stored as given.
	if code, _, _, msg := cliAdd(c, t, "imported", hashSSHA512+"\r\n", nil, "--password-hash-stdin"); code != 0 {
		t.Fatalf("--password-hash-stdin: exit %d: %s", code, msg)
	}
	if h := c.storedHash(t, "imported"); h != hashSSHA512 {
		t.Errorf("the imported hash was stored as %.20q...", h)
	}

	// Refused, each with exit 64 and nothing added.
	refused := []struct {
		name, stdin string
		tty         *fakeTerminal
		flags       []string
		part        string
	}{
		{"empty", "", nil, []string{"--password-stdin"}, "shorter than 12"},
		{"only a newline", "\n", nil, []string{"--password-stdin"}, "shorter than 12"},
		{"11 characters", strings.Repeat("p", 11) + "\n", nil, []string{"--password-stdin"}, "shorter than 12"},
		{"257 characters", strings.Repeat("p", 257), nil, []string{"--password-stdin"}, "longer than 256"},
		{"NUL", "placeholder\x00pass", nil, []string{"--password-stdin"}, "control character"},
		{"ESC", "placeholder\x1bpass", nil, []string{"--password-stdin"}, "control character"},
		{"two trailing newlines", cliPassword + "\n\n", nil, []string{"--password-stdin"}, "control character"},
		{"invalid UTF-8", "placeholder\xffpass", nil, []string{"--password-stdin"}, "not valid UTF-8"},
		{"more than 4 KiB", strings.Repeat("p", 4097), nil, []string{"--password-stdin"}, "longer than 4 KiB"},
		{"both flags", cliPassword, nil, []string{"--password-stdin", "--password-hash-stdin"}, "only one of"},
		{"neither flag without a terminal", cliPassword, nil, nil, "no password"},
		{"different entries at the prompt", "", &fakeTerminal{tty: true, entries: []string{cliPassword, cliPassword2}}, nil, "the two passwords differ"},
		{"a short password at the prompt", "", &fakeTerminal{tty: true, entries: []string{"tiny-pw-9", "tiny-pw-9"}}, nil, "shorter than 12"},
		{"an invalid hash", "{PLAIN}" + cliPassword, nil, []string{"--password-hash-stdin"}, "not supported"},
		{"a hash with a bad cost", "{BLF-CRYPT}$2y$14$" + strings.Repeat("a", 53), nil, []string{"--password-hash-stdin"}, "cost from 04 to 13"},
		{"a password as a hash", cliPassword, nil, []string{"--password-hash-stdin"}, "no scheme prefix"},
	}
	for _, r := range refused {
		var tty terminal = noTTY()
		if r.tty != nil {
			tty = r.tty
			for _, e := range r.tty.entries {
				c.addSecret(e)
			}
		}
		if s := strings.TrimSpace(r.stdin); len(s) >= 5 {
			c.addSecret(s)
		}
		code, out, _, msg := cliAdd(c, t, "refused", r.stdin, tty, r.flags...)
		if code != exitUsage || !strings.Contains(msg, r.part) || out != "" {
			t.Errorf("%s: exit %d, error %q; want 64 and %q", r.name, code, msg, r.part)
		}
		code, _, _, msg = c.run(t, r.stdin, tty, append([]string{"mailbox", "set", "lf@example.org"}, r.flags...)...)
		if r.flags != nil && (code != exitUsage || !strings.Contains(msg, r.part)) {
			t.Errorf("set, %s: exit %d, error %q; want 64 and %q", r.name, code, msg, r.part)
		}
	}
	var n int
	if err := c.conn.QueryRow(context.Background(), "SELECT count(*) FROM mailboxes WHERE local_part = 'refused'").Scan(&n); err != nil || n != 0 {
		t.Errorf("refused inputs added %d mailboxes (%v)", n, err)
	}
	c.wantPassword(t, "lf", cliPassword2)
}

// C4 through the CLI: a placement blocks after its choice; the chosen
// store's server is removed and committed meanwhile; the add exits 1 with
// "the store's server was removed; try again", and no mailbox row is
// left. The imported hash is the marker: neither stdout, stderr nor the
// error message contains it (#111, carried condition 1).
func TestCLIServerRemovedDuringAdd(t *testing.T) {
	c := newCLIDB(t)
	seedCLI(t, c)
	chosen, release := make(chan string, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	c.opts = []store.Option{store.WithAfterChoose(func(gate string) {
		chosen <- gate
		<-release
	})}
	type result struct {
		code             int
		out, errOut, msg string
	}
	done := make(chan result, 1)
	go func() {
		code, out, errOut, msg := cliAdd(c, t, "alice", markerHash, nil, "--password-hash-stdin")
		done <- result{code, out, errOut, msg}
	}()
	select {
	case gate := <-chosen:
		if gate != "store-a" {
			t.Fatalf("chose %s", gate)
		}
	case r := <-done:
		t.Fatalf("the add finished before its choice: %+v", r)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the add never chose a store")
	}
	if _, err := c.conn.Exec(context.Background(), "UPDATE servers SET removed_at = now() WHERE name = 'srv1'"); err != nil {
		t.Fatal(err)
	}
	unblock()
	var r result
	select {
	case r = <-done:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the add did not finish")
	}
	if r.code != exitFailed || r.msg != "the store's server was removed; try again" || r.out != "" {
		t.Errorf("exit %d, error %q, stdout %q", r.code, r.msg, r.out)
	}
	var n int
	if err := c.conn.QueryRow(context.Background(), "SELECT count(*) FROM mailboxes").Scan(&n); err != nil || n != 0 {
		t.Errorf("%d mailboxes after the refusal (%v)", n, err)
	}
	// And nothing can be placed now: both stores are on the removed
	// server.
	c.opts = nil
	c.fail(t, exitFailed, "none is active on a server that is not removed", markerHash, "mailbox", "add", "alice@example.org", "--quota", "1GiB", "--password-hash-stdin")
}

// #111, carried condition 1: a write that PostgreSQL refuses with a
// DETAIL quoting the row, the hash included (a CHECK, here through the
// store API, since the CLI checks every value first), is reported without
// it: the error's text and keepia-mail's exit message hold neither the
// marker hash nor any of its fields.
func TestRefusedWriteHidesHash(t *testing.T) {
	c := newCLIDB(t)
	seedCLI(t, c)
	stores, err := c.st.ListStores(context.Background())
	if err != nil || len(stores) == 0 {
		t.Fatal(stores, err)
	}
	_, err = c.st.CreateMailbox(context.Background(), store.NewMailbox{
		Address: store.Address{LocalPart: "alice", Domain: "example.org"}, PasswordHash: markerHash,
		QuotaBytes: -1, StoreID: stores[0].ID,
	})
	var pgErr interface{ SQLState() string }
	if store.Rule(err) != "mailboxes_quota_bytes_range" || errors.As(err, &pgErr) {
		t.Fatalf("the refused insert: %v (rule %q), want the quota CHECK as a store.RuleError", err, store.Rule(err))
	}
	code, msg := exitStatus(err)
	c.mu.Lock()
	c.outputs = append(c.outputs, err.Error(), msg)
	c.mu.Unlock()
	if code != exitFailed {
		t.Errorf("exit %d", code)
	}
}
