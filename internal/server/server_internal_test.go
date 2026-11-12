package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// hangingDB is a database whose ping blocks until its context ends.
type hangingDB struct{}

func (hangingDB) Ping(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// A database that does not answer makes /healthz give up after its
// timeout and answer 503, instead of hanging with the database.
func TestHealthzTimeout(t *testing.T) {
	if healthTimeout != 2*time.Second {
		t.Errorf("health timeout %v, want 2s as documented", healthTimeout)
	}
	s := New(hangingDB{}, slog.New(slog.DiscardHandler))
	s.healthTimeout = time.Millisecond
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	}()
	select {
	case <-done:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("/healthz did not return while the database hangs")
	}
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "database unavailable\n" {
		t.Errorf("hanging database: %d %q, want 503", rec.Code, rec.Body.String())
	}
}

// The HTTP server bounds every phase of a request.
func TestHTTPServerLimits(t *testing.T) {
	srv := newHTTPServer(http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 30*time.Second ||
		srv.WriteTimeout != 30*time.Second || srv.IdleTimeout != 2*time.Minute || srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("limits: header %v, read %v, write %v, idle %v, max header bytes %d",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
}
