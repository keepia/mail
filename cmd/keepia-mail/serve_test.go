package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

// syncBuffer is a bytes.Buffer safe for concurrent writes and reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// execute runs the root command in-process with args and returns its
// error, its standard output and its standard error (the log).
func execute(ctx context.Context, o options, args ...string) (stdout, stderr string, err error) {
	root := newRootCmd(o)
	root.SetArgs(args)
	var out, errOut syncBuffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	err = root.ExecuteContext(ctx)
	return out.String(), errOut.String(), err
}

// startServe runs serve on 127.0.0.1:0 against the database in
// KEEPIA_DATABASE_URL until the test ends, and returns its address once it
// listens (the ready hook), and a function that stops it and returns its
// error. Without KEEPIA_KEK_FILE it sets one in a new directory.
func startServe(t *testing.T) (addr string, stop func() error) {
	t.Helper()
	addr, stop, _ = startServeLog(t)
	return addr, stop
}

// startServeLog is startServe that also returns serve's log.
func startServeLog(t *testing.T) (addr string, stop func() error, log *syncBuffer) {
	t.Helper()
	if os.Getenv(config.EnvKEKFile) == "" {
		t.Setenv(config.EnvKEKFile, filepath.Join(t.TempDir(), "kek"))
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	addrc := make(chan net.Addr, 1)
	done := make(chan error, 1)
	log = &syncBuffer{}
	go func() {
		root := newRootCmd(options{ready: func(a net.Addr) { addrc <- a }})
		root.SetArgs([]string{"serve", "--listen", "127.0.0.1:0"})
		root.SetOut(io.Discard)
		root.SetErr(log)
		done <- root.ExecuteContext(ctx)
	}()
	select {
	case a := <-addrc:
		addr = a.String()
	case err := <-done:
		t.Fatalf("serve returned before it listened: %v\n%s", err, log)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("serve did not listen")
	}
	return addr, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(testwait.Limit(t)):
			t.Fatal("serve did not return after cancel")
			return nil
		}
	}, log
}

// getHealthz is GET /healthz on addr: the status code and body.
func getHealthz(t *testing.T, addr string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: testwait.Limit(t), Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// baselineApplied tells whether the database at dbURL has version 1 in
// goose_db_version; false when the table does not exist.
func baselineApplied(t *testing.T, dbURL string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// Two queries: PostgreSQL resolves the table of a subquery before it
	// runs, so one query fails when the table is missing.
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		return false
	}
	var applied bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM goose_db_version WHERE version_id = 1 AND is_applied)`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	return applied
}

// serve on an unmigrated database migrates it, then listens and answers
// /healthz; a cancel stops it without an error.
func TestServeMigratesAndServes(t *testing.T) {
	dbURL := storetest.NewUnmigrated(t)
	t.Setenv(config.EnvDatabaseURL, dbURL)

	addr, stop := startServe(t)
	if code, body := getHealthz(t, addr); code != http.StatusOK || body != "ok\n" {
		t.Errorf("healthz: %d %q", code, body)
	}
	if !baselineApplied(t, dbURL) {
		t.Error("serve listens, but version 1 is not in goose_db_version")
	}
	if err := stop(); err != nil {
		t.Errorf("serve after cancel: %v", err)
	}
}

// When another session holds the migration lock past the lock timeout,
// serve fails with an error naming the lock and never listens.
func TestServeFailsOnMigrationLock(t *testing.T) {
	ctx := context.Background()
	dbURL := storetest.NewUnmigrated(t)
	t.Setenv(config.EnvDatabaseURL, dbURL)
	// The holder connects to the test's own database: advisory locks are
	// per database.
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrationLockID); err != nil {
		t.Fatal(err)
	}

	// A serve that listens despite the failed migrations is stopped at
	// once, so the test fails instead of hanging.
	sctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var ready atomic.Bool
	_, log, err := execute(sctx, options{
		ready:        func(net.Addr) { ready.Store(true); cancel() },
		storeOptions: []store.Option{store.WithMigrationLockTimeout(1, 2)},
	}, "serve", "--listen", "127.0.0.1:0")
	if !errors.Is(err, store.ErrMigrationLock) {
		t.Fatalf("serve with the lock held: %v, want ErrMigrationLock", err)
	}
	id := strconv.FormatInt(store.MigrationLockID, 10)
	if !strings.Contains(err.Error(), "migration lock") || !strings.Contains(err.Error(), id) {
		t.Errorf("error %q does not name the migration lock %s", err, id)
	}
	if !strings.Contains(log, "migration lock not acquired") || !strings.Contains(log, "lock_id="+id) {
		t.Errorf("log does not name the migration lock:\n%s", log)
	}
	if ready.Load() {
		t.Error("serve listened although the migrations failed")
	}
	if code, _ := exitStatus(err); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
}

// A database URL that fails serve and migrate, whether it does not parse
// or its server is unreachable, never shows its password in the error or
// the log: also not the part after an unescaped '@' in the password,
// which pgx would take for the host.
func TestServeErrorHidesPassword(t *testing.T) {
	const (
		password = "test-password-not-real"
		// atPassword has an unescaped '@'; secrets lists its parts.
		atPassword = "test-pass@word-not-real"
	)
	secrets := []string{password, atPassword, "test-pass", "word-not-real", "pa-one", "pa-two", "pa-three"}
	well := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("keepia", password),
		Host:     closedPort(t),
		Path:     "/keepia",
		RawQuery: "sslmode=disable&connect_timeout=5",
	}
	for name, dbURL := range map[string]string{
		// Parses; the connect fails.
		"unreachable": well.String(),
		// Does not parse: pgx's parse error, masked by store.Open.
		"bad sslmode": "postgres://keepia:" + password + "@" + closedPort(t) + "/keepia?sslmode=bogus",
		// An unescaped '@' with a valid port: without the check, the
		// connect error names the host "word-not-real@127.0.0.1".
		"at, connect": "postgres://keepia:" + atPassword + "@" + closedPort(t) + "/keepia?sslmode=disable&connect_timeout=5",
		// An unescaped '@' with an invalid port: the parse error.
		"at, bad port": "postgres://keepia:" + atPassword + "@127.0.0.1:x/keepia",
		// An unescaped '@' and then '/', '?' or '#': without the check
		// the rest lands in the database name or the query, and pgx's
		// errors print it (database=word-not-real@…, lookup test-pass).
		"at, slash": "postgres://keepia:pa-one@pa-two/pa-three@" + closedPort(t) + "/keepia?connect_timeout=5",
		"at, query": "postgres://keepia:pa-one@pa-two?x=pa-three@" + closedPort(t) + "/keepia",
		"at, hash":  "postgres://keepia:pa-one@pa-two#pa-three@" + closedPort(t) + "/keepia",
		// Only a '/' in the password, after a number: the rest lands in
		// the database name.
		"slash, port-like": "postgres://keepia:5432/pa-three@" + closedPort(t) + "/keepia?connect_timeout=5",
		// Not a URL to pgx: it would read these as keyword/value, with
		// the whole URL as a parameter name that a server echoes, or with
		// a password that sets the host.
		"not a URL, leading space": " postgres://keepia:pa-one@" + closedPort(t) + "/keepia?sslmode=disable",
		"not a URL, upper case":    "POSTGRES://keepia:pa-one@" + closedPort(t) + "/keepia?sslmode=disable",
		"not a URL, mixed case":    "Postgres://keepia:pa-one@" + closedPort(t) + "/keepia",
		"not a URL, trailing tab":  "postgres://keepia:pa-one@" + closedPort(t) + "/keepia?sslmode=disable\t",
		"not a URL, keyword/value": "host=127.0.0.1 port=1 user=keepia password=pa-one host=pa-two dbname=keepia",
		// Percent-encoded as it must be: the URL is used, and the
		// connect fails without showing the password.
		"encoded": "postgres://keepia:pa-one%40pa-two%2Fpa-three@" + closedPort(t) + "/keepia?sslmode=disable&connect_timeout=5",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(config.EnvDatabaseURL, dbURL)
			for _, args := range [][]string{{"serve", "--listen", "127.0.0.1:0"}, {"migrate"}} {
				out, log, err := execute(t.Context(), options{}, args...)
				if err == nil {
					t.Fatalf("%v succeeded with %s", args, name)
				}
				if strings.HasPrefix(name, "at, ") || strings.HasPrefix(name, "slash, ") {
					if !strings.Contains(err.Error(), "%40") {
						t.Errorf("%v: %v, want the percent-encoding error", args, err)
					}
				}
				if strings.HasPrefix(name, "not a URL, ") && !strings.Contains(err.Error(), "must start with postgres:// or postgresql://") {
					t.Errorf("%v: %v, want the URL-form error", args, err)
				}
				if name == "encoded" && !strings.Contains(err.Error(), "connect to database") {
					t.Errorf("%v: %v, want a connect error: the encoded URL must be used", args, err)
				}
				for _, s := range secrets {
					if strings.Contains(err.Error(), s) || strings.Contains(log, s) || strings.Contains(out, s) {
						t.Errorf("%v: %q leaked:\nerror: %v\nlog: %s", args, s, err, log)
					}
				}
			}
		})
	}
}

// closedPort is a loopback host:port where nothing listens.
func closedPort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// serve and migrate need KEEPIA_DATABASE_URL and say so; a bad --listen
// fails before anything connects.
func TestConfigErrors(t *testing.T) {
	t.Setenv(config.EnvDatabaseURL, "")
	for _, args := range [][]string{{"serve"}, {"migrate"}, {"migrate", "status"}} {
		_, _, err := execute(t.Context(), options{}, args...)
		if err == nil || !strings.Contains(err.Error(), config.EnvDatabaseURL) {
			t.Errorf("%v without a URL: %v, want an error naming %s", args, err, config.EnvDatabaseURL)
		}
	}

	t.Setenv(config.EnvDatabaseURL, "postgres://keepia@"+closedPort(t)+"/keepia")
	_, _, err := execute(t.Context(), options{}, "serve", "--listen", "nope")
	if err == nil || !strings.Contains(err.Error(), `listen address "nope"`) {
		t.Errorf("bad --listen: %v", err)
	}
	t.Setenv(config.EnvLogLevel, "loud")
	_, _, err = execute(t.Context(), options{}, "serve")
	if err == nil || !strings.Contains(err.Error(), config.EnvLogLevel) {
		t.Errorf("bad log level: %v", err)
	}
}

// embeddedMigrations lists the migrations that the store embeds
// (internal/store/migrations/*.sql) in version order.
func embeddedMigrations(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../../internal/store/migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		files = append(files, filepath.Base(p))
	}
	return files
}

// migrate applies every embedded migration once, in order; migrate status
// shows them.
func TestMigrateCommand(t *testing.T) {
	files := embeddedMigrations(t)
	dbURL := storetest.NewUnmigrated(t)
	t.Setenv(config.EnvDatabaseURL, dbURL)

	out, _, err := execute(t.Context(), options{}, "migrate", "status")
	if err != nil {
		t.Fatalf("status before: %v\n%s", err, out)
	}
	checkStates(t, "status before", out, files, "pending")
	want := ""
	for _, f := range files {
		want += "applied " + f + "\n"
	}
	if out, _, err = execute(t.Context(), options{}, "migrate"); err != nil || out != want {
		t.Fatalf("migrate: %v\n%s, want\n%s", err, out, want)
	}
	if out, _, err = execute(t.Context(), options{}, "migrate"); err != nil || out != "database schema is up to date\n" {
		t.Fatalf("second migrate: %v\n%s", err, out)
	}
	if out, _, err = execute(t.Context(), options{}, "migrate", "status"); err != nil {
		t.Fatalf("status after: %v\n%s", err, out)
	}
	checkStates(t, "status after", out, files, "applied")
}

// checkStates fails the test unless the table of migrate status lists
// exactly files, in order, each in state.
func checkStates(t *testing.T, step, out string, files []string, state string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(files)+1 || strings.Join(strings.Fields(lines[0]), " ") != "MIGRATION STATE APPLIED AT" {
		t.Fatalf("%s: want a header and %d rows\n%s", step, len(files), out)
	}
	for i, f := range files {
		if fields := strings.Fields(lines[i+1]); len(fields) < 2 || fields[0] != f || fields[1] != state {
			t.Fatalf("%s: row %d is %q, want %s %s", step, i+1, lines[i+1], f, state)
		}
	}
}

// migrate fails, naming the lock, while another session holds it.
func TestMigrateCommandLockTimeout(t *testing.T) {
	ctx := context.Background()
	dbURL := storetest.NewUnmigrated(t)
	t.Setenv(config.EnvDatabaseURL, dbURL)
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrationLockID); err != nil {
		t.Fatal(err)
	}
	_, _, err = execute(t.Context(), options{storeOptions: []store.Option{store.WithMigrationLockTimeout(1, 1)}}, "migrate")
	if !errors.Is(err, store.ErrMigrationLock) || !strings.Contains(err.Error(), strconv.FormatInt(store.MigrationLockID, 10)) {
		t.Fatalf("migrate with the lock held: %v", err)
	}
	if baselineApplied(t, dbURL) {
		t.Error("migrate applied version 1 while the lock was held")
	}
}
