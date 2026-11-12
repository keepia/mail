package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/server"
	"github.com/keepia/mail/internal/store"
)

func newServeCmd(o options) *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Apply pending migrations, then serve HTTP (health endpoint /healthz)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Load(os.Getenv)
			if cmd.Flags().Changed("listen") {
				cfg.Listen = listen
			}
			return runServe(cmd.Context(), cfg, cmd.ErrOrStderr(), o)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "listen address host:port (default $"+config.EnvListen+" or "+config.DefaultListen+")")
	return cmd
}

// runServe opens the store, applies the pending migrations under the
// migration lock and then serves until ctx is cancelled. The listener
// opens only after the migrations: when they fail, also when the
// migration lock is not free in time, it returns the error and never
// listens. It logs to logw and never logs the database URL.
func runServe(ctx context.Context, cfg config.Config, logw io.Writer, o options) error {
	level, err := config.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return err
	}
	if err := config.CheckListen(cfg.Listen); err != nil {
		return err
	}
	dbURL, err := cfg.RequireDatabaseURL()
	if err != nil {
		return err
	}
	log := newLogger(logw, level)

	st, err := store.Open(ctx, dbURL, append([]store.Option{store.ForMigrations()}, o.storeOptions...)...)
	if err != nil {
		return err
	}
	defer st.Close()
	applied, err := st.Migrate(ctx)
	if err != nil {
		if errors.Is(err, store.ErrMigrationLock) {
			log.Error("migration lock not acquired; not serving", "lock_id", store.MigrationLockID, "err", err)
		}
		return fmt.Errorf("migrate: %w", err)
	}
	for _, m := range applied {
		log.Info("applied migration", "migration", m)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("listening", "addr", ln.Addr().String())
	if o.ready != nil {
		o.ready(ln.Addr())
	}
	return server.New(st, log).Serve(ctx, ln)
}
