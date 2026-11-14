package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/gatebundle"
	"github.com/keepia/mail/internal/join"
	"github.com/keepia/mail/internal/store/storetest"
)

// executeIn is execute with stdin.
func executeIn(ctx context.Context, stdin io.Reader, args ...string) (stdout, stderr string, err error) {
	root := newRootCmd(options{})
	root.SetArgs(args)
	var out, errOut syncBuffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetIn(stdin)
	err = root.ExecuteContext(ctx)
	return out.String(), errOut.String(), err
}

// deployment runs serve's first start against a new database, with the
// KEK file and the control gate directory in new directories, and
// returns the gate directory.
func deployment(t *testing.T) string {
	t.Helper()
	t.Setenv(config.EnvDatabaseURL, storetest.NewUnmigrated(t))
	t.Setenv(config.EnvKEKFile, filepath.Join(t.TempDir(), "kek"))
	gate := t.TempDir()
	t.Setenv(config.EnvControlGateDir, gate)
	_, stop, _ := startServeLog(t)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	return gate
}

const warningLine = "warning: control secrets never exported: "

// J1, L3: server add prints one token on stdout and only the warning on
// stderr; server list shows the server and no secret.
func TestServerAddPrintsOneToken(t *testing.T) {
	deployment(t)
	ctx := t.Context()
	out, errOut, err := execute(ctx, options{}, "server", "add", "s1", "--roles", "store,edge")
	if err != nil {
		t.Fatalf("server add: %v\n%s", err, errOut)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout has %d lines", len(lines))
	}
	tok, err := join.ParseToken(lines[0])
	if err != nil {
		t.Fatalf("stdout is not a token: %v", err)
	}
	errLines := strings.Split(strings.TrimSuffix(errOut, "\n"), "\n")
	if len(errLines) != 1 || !strings.HasPrefix(errLines[0], warningLine) || !strings.Contains(errLines[0], "./km secrets export") {
		t.Errorf("stderr: %q", errOut)
	}
	if strings.Contains(errOut, lines[0][len(join.TokenPrefix):]) {
		t.Error("stderr holds the token")
	}
	out, _, err = execute(ctx, options{}, "server", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "s1") || !strings.Contains(out, "store,edge") || strings.Contains(out, lines[0][len(join.TokenPrefix):]) ||
		strings.Contains(out, string(tok.Secret[:])) {
		t.Errorf("server list:\n%s", out)
	}
	tokOut, _, err := execute(ctx, options{}, "server", "token", "s1", "--ttl", "5m")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := join.ParseToken(strings.TrimSpace(tokOut)); err != nil || strings.TrimSpace(tokOut) == lines[0] {
		t.Errorf("server token: %q, %v", tokOut, err)
	}
}

// L1, L2: server add refuses bad names, roles, duplicates and lifetimes;
// server remove refuses the control server.
func TestServerCommandsRefuse(t *testing.T) {
	deployment(t)
	ctx := t.Context()
	for _, args := range [][]string{
		{"server", "add", "S1", "--roles", "store"},
		{"server", "add", "s1.example", "--roles", "store"},
		{"server", "add", "s1"},
		{"server", "add", "s1", "--roles", "store,mail"},
		{"server", "add", "s1", "--roles", "store,store"},
		{"server", "add", "s1", "--roles", "store,"},
		{"server", "add", "s1", "--roles", "store", "--ttl", "4m59s"},
		{"server", "add", "s1", "--roles", "store", "--ttl", "24h1s"},
	} {
		if out, _, err := execute(ctx, options{}, args...); err == nil || out != "" {
			t.Errorf("%v: %v, stdout %q", args, err, out)
		}
	}
	if _, _, err := execute(ctx, options{}, "server", "add", "c1", "--roles", "control", "--ttl", "24h"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := execute(ctx, options{}, "server", "add", "c1", "--roles", "edge"); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("duplicate: %v", err)
	}
	if _, _, err := execute(ctx, options{}, "server", "remove", "c1"); err == nil || !strings.Contains(err.Error(), "control server cannot be removed") {
		t.Errorf("remove control: %v", err)
	}
	if _, _, err := execute(ctx, options{}, "server", "add", "s2", "--roles", "store"); err != nil {
		t.Fatal(err)
	}
	out, _, err := execute(ctx, options{}, "server", "remove", "s2")
	if err != nil || !strings.Contains(out, "removed s2") {
		t.Errorf("remove s2: %q, %v", out, err)
	}
}

// E5, E6, ST1, E7: the passphrase comes only from stdin, never from a
// device; an export stops the warning at the next start; status shows
// the ids; restore brings back a lost KEK.
func TestSecretsCommands(t *testing.T) {
	gate := deployment(t)
	ctx := t.Context()
	pass := "correct horse battery staple\n"

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	if _, _, err := executeIn(ctx, devNull, "secrets", "export"); err == nil || !strings.Contains(err.Error(), "terminal or another device") {
		t.Errorf("stdin /dev/null: %v", err)
	}
	if _, _, err := executeIn(ctx, strings.NewReader("too short\n"), "secrets", "export"); err == nil || !strings.Contains(err.Error(), "shorter than 16") {
		t.Errorf("short passphrase: %v", err)
	}
	if _, _, err := executeIn(ctx, strings.NewReader(pass), "secrets", "export", "--passphrase", "x"); err == nil {
		t.Error("export took a passphrase flag")
	}
	for _, name := range []string{"export", "restore"} {
		cmd, _, err := newRootCmd(options{}).Find([]string{"secrets", name})
		if err != nil || cmd.Flags().HasFlags() {
			t.Errorf("secrets %s has flags (none may take a passphrase): %v", name, err)
		}
	}

	status, errOut, err := execute(ctx, options{}, "secrets", "status")
	if err != nil || !strings.Contains(status, "kek_id") || !strings.Contains(status, "last_export    never") || !strings.HasPrefix(errOut, warningLine) {
		t.Fatalf("status before the export: %v\n%s%s", err, status, errOut)
	}

	export, errOut, err := executeIn(ctx, strings.NewReader(pass), "secrets", "export")
	if err != nil || !strings.HasPrefix(export, "-----BEGIN KEEPIA MAIL SECRETS EXPORT-----\n") {
		t.Fatalf("export: %v\n%s", err, errOut)
	}
	if strings.Contains(errOut, warningLine) {
		t.Errorf("export warned: %q", errOut)
	}
	if _, errOut, err := execute(ctx, options{}, "server", "list"); err != nil || errOut != "" {
		t.Errorf("after the export, server list's stderr: %q, %v", errOut, err)
	}
	_, stop, log := startServeLog(t)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if len(logLines(log.String(), "never exported")) != 0 || len(logLines(log.String(), "control secrets loaded")) != 1 {
		t.Errorf("serve after the export:\n%s", log)
	}

	kek := os.Getenv(config.EnvKEKFile)
	if err := os.Remove(kek); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeIn(ctx, strings.NewReader(pass+export), "secrets", "restore"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if fi, err := os.Stat(kek); err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("restored KEK: %v, %v", fi, err)
	}
	if _, _, err := executeIn(ctx, strings.NewReader(pass+export), "secrets", "restore"); err == nil {
		t.Error("a second restore over the KEK succeeded")
	}
	addr, stop, log := startServeLog(t)
	if code, _ := getHealthz(t, addr); code != http.StatusOK {
		t.Errorf("healthz after the restore: %d\n%s", code, log)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := gatebundle.Read(gate); err != nil {
		t.Errorf("the gate bundle: %v", err)
	}
}

// K1, K6 (serve): the first start writes the control gate's bundle before
// serve listens, and a later start rewrites a deleted one before it
// listens again.
func TestServeWritesTheGateBundleBeforeReady(t *testing.T) {
	gate := deployment(t)
	if g, err := gatebundle.ReadGeneration(gate); err != nil || g != 1 {
		t.Fatalf("after the first start: generation %d, %v", g, err)
	}
	if _, err := gatebundle.Read(gate); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(gate, gatebundle.BundleFile)); err != nil {
		t.Fatal(err)
	}
	// startServeLog returns at serve's ready hook, once it listens.
	_, stop, _ := startServeLog(t)
	_, seen := gatebundle.Read(gate)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if seen != nil {
		t.Errorf("the bundle when serve was ready: %v", seen)
	}
	if g, err := gatebundle.ReadGeneration(gate); err != nil || g != 2 {
		t.Errorf("generation %d, %v, want 2", g, err)
	}
}
