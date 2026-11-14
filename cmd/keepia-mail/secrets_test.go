package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/store/storetest"
)

// logLines are the lines of log that contain s.
func logLines(log, s string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, s) {
			out = append(out, l)
		}
	}
	return out
}

// B1, B2, C1 (log part). The first serve creates the secrets and logs one
// WARN that names the KEK file and the volume; the second loads them, logs
// no "created" line, and repeats the warning while they were never
// exported (CD28).
func TestServeCreatesSecretsAndWarns(t *testing.T) {
	t.Setenv(config.EnvDatabaseURL, storetest.NewUnmigrated(t))
	kek := filepath.Join(t.TempDir(), "kek")
	t.Setenv(config.EnvKEKFile, kek)

	addr, stop, log := startServeLog(t)
	if code, body := getHealthz(t, addr); code != http.StatusOK || body != "ok\n" {
		t.Errorf("healthz after the first start: %d %q", code, body)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	created := logLines(log.String(), "control secrets created")
	if len(created) != 1 || !strings.Contains(created[0], "level=WARN") ||
		!strings.Contains(created[0], kek+" on the volume keepia-kek") ||
		!strings.Contains(created[0], "Losing it loses all mail") {
		t.Errorf("first start: created lines %q\n%s", created, log)
	}
	fi, err := os.Stat(kek)
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("KEK file: %v, %v", fi, err)
	}

	addr, stop, log = startServeLog(t)
	if code, _ := getHealthz(t, addr); code != http.StatusOK {
		t.Errorf("healthz after the second start: %d", code)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if lines := logLines(log.String(), "control secrets created"); len(lines) != 0 {
		t.Errorf("second start logged %q", lines)
	}
	if lines := logLines(log.String(), "control secrets never exported"); len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") {
		t.Errorf("second start: reminder lines %q\n%s", lines, log)
	}
}

// B3. With the secrets in the database and the KEK file gone, serve is
// locked: it logs one ERROR, listens, answers /healthz with 503 "secrets
// unavailable" until it is cancelled, and writes no file.
func TestServeLockedWithoutKEK(t *testing.T) {
	t.Setenv(config.EnvDatabaseURL, storetest.NewUnmigrated(t))
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	t.Setenv(config.EnvKEKFile, kek)
	_, stop, _ := startServeLog(t)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(kek); err != nil {
		t.Fatal(err)
	}

	addr, stop, log := startServeLog(t)
	if code, body := getHealthz(t, addr); code != http.StatusServiceUnavailable || body != "secrets unavailable\n" {
		t.Errorf("healthz while locked: %d %q", code, body)
	}
	// Still serving: a second request gets the same answer.
	if code, _ := getHealthz(t, addr); code != http.StatusServiceUnavailable {
		t.Errorf("second healthz while locked: %d", code)
	}
	if err := stop(); err != nil {
		t.Errorf("locked serve after cancel: %v", err)
	}
	lines := logLines(log.String(), "control secrets locked")
	if len(lines) != 1 || !strings.Contains(lines[0], "level=ERROR") || !strings.Contains(lines[0], "KEK missing") {
		t.Errorf("locked lines %q\n%s", lines, log)
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Errorf("a locked serve wrote into the KEK directory: %v, %v", ents, err)
	}
}
