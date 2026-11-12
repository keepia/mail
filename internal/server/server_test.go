package server_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keepia/mail/internal/server"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

func get(t *testing.T, h http.Handler, method, path string) (int, string, http.Header) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return rec.Code, rec.Body.String(), rec.Header()
}

// /healthz answers 200 while the database answers, and 503 once it does
// not.
func TestHealthz(t *testing.T) {
	st := storetest.New(t)
	h := server.New(st, slog.New(slog.DiscardHandler)).Handler()

	code, body, hdr := get(t, h, http.MethodGet, "/healthz")
	if code != http.StatusOK || body != "ok\n" {
		t.Fatalf("database up: %d %q", code, body)
	}
	if hdr.Get("Cache-Control") != "no-store" || hdr.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("headers: %v", hdr)
	}

	st.Close()
	if code, body, _ = get(t, h, http.MethodGet, "/healthz"); code != http.StatusServiceUnavailable || body != "database unavailable\n" {
		t.Fatalf("database closed: %d %q", code, body)
	}
}

type okDB struct{}

func (okDB) Ping(context.Context) error { return nil }

func TestRoutes(t *testing.T) {
	h := server.New(okDB{}, slog.New(slog.DiscardHandler)).Handler()
	if code, _, _ := get(t, h, http.MethodPost, "/healthz"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz: %d", code)
	}
	if code, _, _ := get(t, h, http.MethodGet, "/"); code != http.StatusNotFound {
		t.Errorf("GET /: %d", code)
	}
}

// Serve answers on its listener and returns nil once ctx is cancelled.
func TestServeShutsDownOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.New(okDB{}, slog.New(slog.DiscardHandler)).Serve(ctx, ln) }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: testwait.Limit(t), Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Fatalf("healthz: %d %q", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancel: %v", err)
		}
	case <-time.After(testwait.Limit(t)):
		t.Fatal("serve did not return after cancel")
	}
}
