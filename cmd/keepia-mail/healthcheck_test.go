package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/store/storetest"
)

func healthcheck(t *testing.T, addr string) int {
	t.Helper()
	_, _, err := execute(t.Context(), options{}, "healthcheck", "--listen", addr)
	code, _ := exitStatus(err)
	return code
}

// healthcheck exits 0 against a running serve.
func TestHealthcheckServe(t *testing.T) {
	t.Setenv(config.EnvDatabaseURL, storetest.NewUnmigrated(t))
	addr, stop := startServe(t)
	// It needs no database URL.
	t.Setenv(config.EnvDatabaseURL, "")
	if code := healthcheck(t, addr); code != 0 {
		t.Errorf("healthcheck against serve: exit %d", code)
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
}

// healthcheck exits 1 on any answer but 200, and when nothing listens.
func TestHealthcheckFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if code := healthcheck(t, addr); code != 1 {
		t.Errorf("against a 503: exit %d, want 1", code)
	}
	if code := healthcheck(t, closedPort(t)); code != 1 {
		t.Errorf("against a closed port: exit %d, want 1", code)
	}
}

func TestHealthURL(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8080": "http://127.0.0.1:8080/healthz",
		"0.0.0.0:8080":   "http://127.0.0.1:8080/healthz",
		":8080":          "http://127.0.0.1:8080/healthz",
		"[::]:8080":      "http://127.0.0.1:8080/healthz",
		"[::1]:8080":     "http://[::1]:8080/healthz",
		"keepia:8080":    "http://keepia:8080/healthz",
	} {
		if got, err := healthURL(addr); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", addr, got, err, want)
		}
	}
	if _, err := healthURL("nope"); err == nil {
		t.Error("nope accepted")
	}
}
