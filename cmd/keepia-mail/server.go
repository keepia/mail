package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/join"
	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/secrets"
	"github.com/keepia/mail/internal/store"
)

func newServerCmd(o options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Add, list and remove servers, and create their join tokens",
	}
	cmd.AddCommand(newServerAddCmd(o), newServerTokenCmd(o), newServerRemoveCmd(o), newServerListCmd(o))
	return cmd
}

// cliEnv is what a server or secrets command works with: the store and
// the configuration.
type cliEnv struct {
	st  *store.Store
	cfg config.Config
}

// openCLI opens the store with the database URL from the environment.
func openCLI(ctx context.Context, o options) (*cliEnv, error) {
	cfg := config.Load(os.Getenv)
	dbURL, err := cfg.RequireDatabaseURL()
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, dbURL, o.storeOptions...)
	if err != nil {
		return nil, err
	}
	return &cliEnv{st: st, cfg: cfg}, nil
}

func (e *cliEnv) secretsConfig() secrets.Config { return secrets.Config{KEKFile: e.cfg.KEKFile} }

// keyring reads the secrets (under the bootstrap lock, shared) and prints
// CD28's warning to stderr while they were never exported.
func (e *cliEnv) keyring(ctx context.Context, stderr io.Writer) (*secrets.Keyring, error) {
	kr, err := secrets.Read(ctx, e.st, e.secretsConfig())
	if err != nil {
		return nil, err
	}
	warnUnexported(stderr, kr.Exported(), e.cfg.KEKFile)
	return kr, nil
}

// warnUnexported prints CD28's warning while the secrets were never
// exported.
func warnUnexported(stderr io.Writer, exported bool, kekFile string) {
	if !exported {
		fmt.Fprintln(stderr, "warning: control secrets never exported: "+kekWarning(kekFile))
	}
}

func newServerAddCmd(o options) *cobra.Command {
	var (
		roles string
		ttl   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "add <name> --roles <role,...>",
		Short: "Add a server and print its one-time join token on stdout",
		Long: "Adds the server <name> (a lowercase DNS label) with its roles (control, edge, store, filter, groupware)\n" +
			"and prints a join token, valid for --ttl (5m to 24h), once on stdout. The token is not stored and never logged.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rs := splitRoles(roles)
			if err := join.CheckServerSpec(args[0], rs); err != nil {
				return err
			}
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			kr, err := e.keyring(ctx, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			t, err := join.AddServer(ctx, e.st, kr.Anchor(pki.AnchorService).Cert, args[0], rs, ttl, time.Now())
			if errors.Is(err, store.ErrExists) {
				return fmt.Errorf("a server named %s exists already", args[0])
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), t.String())
			return err
		},
	}
	cmd.Flags().StringVar(&roles, "roles", "", "the server's roles, comma-separated: control, edge, store, filter, groupware")
	cmd.Flags().DurationVar(&ttl, "ttl", join.DefaultTTL, "the token's lifetime, from 5m to 24h")
	return cmd
}

// splitRoles splits a comma-separated role list; empty items stay, so
// that CheckServerSpec refuses them.
func splitRoles(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func newServerTokenCmd(o options) *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "token <name>",
		Short: "Print a new join token for a server that has not joined; older tokens stop working",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			kr, err := e.keyring(ctx, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			t, err := join.NewToken(ctx, e.st, kr.Anchor(pki.AnchorService).Cert, args[0], ttl, time.Now())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), t.String())
			return err
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", join.DefaultTTL, "the token's lifetime, from 5m to 24h")
	return cmd
}

func newServerRemoveCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a server: revoke its certificates and tokens and reissue the revocation lists",
		Long: "Marks the server removed, revokes every certificate of it, invalidates its tokens and reissues the\n" +
			"revocation lists, in one transaction. The control server, and a store server that still holds\n" +
			"mailboxes, cannot be removed. The row is kept for the lists.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			kr, err := e.keyring(ctx, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			n, err := pki.RevokeServer(ctx, e.st, kr, args[0], time.Now())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "removed %s: %d certificates revoked, revocation lists reissued\n", args[0], n)
			return err
		},
	}
}

func newServerListCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the servers: roles, joined, removed and the agent certificate's expiry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			kr, err := secrets.Read(ctx, e.st, e.secretsConfig())
			if err != nil {
				return err
			}
			warnUnexported(cmd.ErrOrStderr(), kr.Exported(), e.cfg.KEKFile)
			servers, err := e.st.ListServers(ctx)
			if err != nil {
				return err
			}
			expiry, err := e.st.AgentCertificateExpiries(ctx)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tROLES\tJOINED\tREMOVED\tAGENT CERTIFICATE EXPIRES")
			for _, s := range servers {
				agent := "-"
				if t, ok := expiry[s.ID]; ok && s.RemovedAt == nil {
					agent = timeText(&t)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, strings.Join(s.Roles, ","), timeText(s.JoinedAt), timeText(s.RemovedAt), agent)
			}
			return w.Flush()
		},
	}
}

func timeText(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.DateTime) + " UTC"
}
