// Package server is Keepia Mail's HTTP server. For now it answers the
// health endpoint only.
package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Pinger checks that the database answers.
type Pinger interface {
	Ping(ctx context.Context) error
}

const (
	// healthTimeout bounds the database check of /healthz.
	healthTimeout = 2 * time.Second
	// shutdownTimeout bounds the graceful shutdown on cancel.
	shutdownTimeout = 10 * time.Second
)

// Server serves Keepia Mail's HTTP endpoints.
type Server struct {
	db  Pinger
	log *slog.Logger
	// healthTimeout bounds the database check of /healthz (healthTimeout;
	// tests shorten it).
	healthTimeout time.Duration
	// secretsLocked: the control secrets could not be opened (#96, CD8).
	secretsLocked bool
}

// Option configures New.
type Option func(*Server)

// SecretsUnavailable marks the control secrets as locked (#96, CD8):
// /healthz then answers 503 "secrets unavailable". serve keeps running
// in that state, so that a restore can still run in its container.
func SecretsUnavailable() Option {
	return func(s *Server) { s.secretsLocked = true }
}

// New returns a server whose health endpoint checks db.
func New(db Pinger, log *slog.Logger, opts ...Option) *Server {
	s := &Server{db: db, log: log, healthTimeout: healthTimeout}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Handler returns the routes:
//
//   - GET /healthz: "200 ok" when a query on the database succeeds within
//     2 s, "503 database unavailable" otherwise, and "503 secrets
//     unavailable" while the control secrets are locked
//     (SecretsUnavailable). It reveals nothing else and needs no login.
//     serve opens its listener only after the migrations and the secrets'
//     bootstrap, so a healthy answer also means the schema is current and
//     the secrets are loaded.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.healthTimeout)
	defer cancel()
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if s.secretsLocked {
		// serve logged the reason once at its start.
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "secrets unavailable\n")
		return
	}
	if err := s.db.Ping(ctx); err != nil {
		// The cause goes to the log only, never to the client.
		s.log.Warn("health check: database unavailable", "err", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "database unavailable\n")
		return
	}
	_, _ = io.WriteString(w, "ok\n")
}

// newHTTPServer is the HTTP server for handler, with timeouts on every
// phase of a request: 10 s for the headers (at most 64 KiB), 30 s to read
// and to write, 2 min for an idle keep-alive connection.
func newHTTPServer(handler http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Serve serves on ln until ctx is cancelled, then shuts down gracefully
// within 10 s. It returns nil after a shutdown on cancel, and the error
// that stopped it otherwise. It closes ln.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := newHTTPServer(s.Handler(), s.log)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		err := srv.Shutdown(sctx)
		if serr := <-errc; !errors.Is(serr, http.ErrServerClosed) && err == nil {
			err = serr
		}
		return err
	}
}
