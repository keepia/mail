package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
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
// error.
func startServe(t *testing.T) (addr string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	addrc := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		_, _, err := execute(ctx, options{ready: func(a net.Addr) { addrc <- a }}, "serve", "--listen", "127.0.0.1:0")
		done <- err
	}()
	select {
	case a := <-addrc:
		addr = a.String()
	case err := <-done:
		t.Fatalf("serve returned before it listened: %v", err)
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
	}
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

// A database URL whose server is unreachable fails serve, and neither the
// error nor the log contains the URL's password.
func TestServeErrorHidesPassword(t *testing.T) {
	const password = "test-password-not-real"
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("keepia", password),
		Host:     closedPort(t),
		Path:     "/keepia",
		RawQuery: "sslmode=disable&connect_timeout=5",
	}
	t.Setenv(config.EnvDatabaseURL, u.String())
	_, log, err := execute(t.Context(), options{}, "serve", "--listen", "127.0.0.1:0")
	if err == nil {
		t.Fatal("serve succeeded against an unreachable database")
	}
	if strings.Contains(err.Error(), password) || strings.Contains(log, password) {
		t.Errorf("the password leaked:\nerror: %v\nlog: %s", err, log)
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

// migrate applies the baseline once; migrate status shows it.
func TestMigrateCommand(t *testing.T) {
	dbURL := storetest.NewUnmigrated(t)
	t.Setenv(config.EnvDatabaseURL, dbURL)

	out, _, err := execute(t.Context(), options{}, "migrate", "status")
	if err != nil || !strings.Contains(out, "00001_baseline.sql  pending") {
		t.Fatalf("status before: %v\n%s", err, out)
	}
	if out, _, err = execute(t.Context(), options{}, "migrate"); err != nil || out != "applied 00001_baseline.sql\n" {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	if out, _, err = execute(t.Context(), options{}, "migrate"); err != nil || out != "database schema is up to date\n" {
		t.Fatalf("second migrate: %v\n%s", err, out)
	}
	if out, _, err = execute(t.Context(), options{}, "migrate", "status"); err != nil || !strings.Contains(out, "00001_baseline.sql  applied") {
		t.Fatalf("status after: %v\n%s", err, out)
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
