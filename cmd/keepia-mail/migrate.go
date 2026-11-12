package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/store"
)

func newMigrateCmd(o options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply all pending database migrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openStore(cmd, o)
			if err != nil {
				return err
			}
			defer st.Close()
			applied, err := st.Migrate(cmd.Context())
			if errors.Is(err, store.ErrMigrationLock) {
				return fmt.Errorf("another migration holds the migration lock (PostgreSQL advisory lock %d); try again when it is done: %w",
					store.MigrationLockID, err)
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(applied) == 0 {
				fmt.Fprintln(out, "database schema is up to date")
			}
			for _, m := range applied {
				fmt.Fprintln(out, "applied", m)
			}
			return nil
		},
	}
	cmd.AddCommand(newMigrateStatusCmd(o))
	return cmd
}

func newMigrateStatusCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show applied and pending migrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openStore(cmd, o)
			if err != nil {
				return err
			}
			defer st.Close()
			statuses, err := st.MigrationStatus(cmd.Context())
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "MIGRATION\tSTATE\tAPPLIED AT")
			for _, s := range statuses {
				state, at := "pending", "-"
				if s.Applied {
					state, at = "applied", s.AppliedAt.UTC().Format(time.DateTime)+" UTC"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Path, state, at)
			}
			return w.Flush()
		},
	}
}

// openStore opens the store for a migrate command, with the database URL
// from the environment.
func openStore(cmd *cobra.Command, o options) (*store.Store, error) {
	dbURL, err := config.Load(os.Getenv).RequireDatabaseURL()
	if err != nil {
		return nil, err
	}
	return store.Open(cmd.Context(), dbURL, append([]store.Option{store.ForMigrations()}, o.storeOptions...)...)
}
