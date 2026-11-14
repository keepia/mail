package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/secrets"
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
// migration lock, creates or loads the control secrets (bootstrapSecrets)
// and then serves until ctx is cancelled. The listener opens only after
// both: when the migrations fail, also when the migration lock is not free
// in time, or the bootstrap fails other than by a locked state, it returns
// the error and never listens. It logs to logw and never logs the database
// URL.
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
	srvOpts, err := bootstrapSecrets(ctx, st, cfg, log)
	if err != nil {
		return fmt.Errorf("control secrets: %w", err)
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
	return server.New(st, log, srvOpts...).Serve(ctx, ln)
}

// kekWarning is the warning of CD28 without its last sentence, which #96
// part 2 adds together with `secrets export`.
func kekWarning(kekFile string) string {
	return "the key-encryption key is " + kekFile + " on the volume keepia-kek. " +
		"Losing it loses all mail (the mail_crypt key is sealed under it) and every certificate. " +
		"It is not in a database dump."
}

// bootstrapSecrets creates the control secrets at the first start and
// loads them at every later one (#96, CD6–CD8). It logs the first-start
// warning, and repeats it at every start while the secrets were never
// exported (CD28). A locked state (a missing or wrong KEK, for example) is
// logged once as an ERROR and gives the server option that makes /healthz
// answer 503 "secrets unavailable": serve stays up, so that commands can
// still run in its container. Any other error stops serve before it
// listens.
func bootstrapSecrets(ctx context.Context, st *store.Store, cfg config.Config, log *slog.Logger) ([]server.Option, error) {
	res, err := secrets.Bootstrap(ctx, st, secrets.Config{KEKFile: cfg.KEKFile})
	var lockedErr *secrets.LockedError
	if errors.As(err, &lockedErr) {
		log.Error("control secrets locked: serving /healthz as 503 secrets unavailable until this is fixed and keepia restarted", "err", lockedErr.Error())
		return []server.Option{server.SecretsUnavailable()}, nil
	}
	if err != nil {
		return nil, err
	}
	kr := res.Keyring
	switch {
	case res.Created:
		log.Warn("control secrets created: "+kekWarning(cfg.KEKFile), "kek_id", kr.KEKID().String())
	case !kr.Exported():
		log.Warn("control secrets never exported: "+kekWarning(cfg.KEKFile), "kek_id", kr.KEKID().String())
	default:
		log.Info("control secrets loaded", "kek_id", kr.KEKID().String())
	}
	return nil, nil
}
