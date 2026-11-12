// Command keepia-mail is Keepia Mail's service and command-line tool.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd(options{}).ExecuteContext(ctx)
	stop()
	code, msg := exitStatus(err)
	if msg != "" {
		fmt.Fprintln(os.Stderr, "error:", msg)
	}
	os.Exit(code)
}

// options are hooks for tests; main passes the zero value.
type options struct {
	// ready, when set, is called with the listen address once serve
	// listens.
	ready func(net.Addr)
	// storeOptions are added to every store.Open.
	storeOptions []store.Option
}

func newRootCmd(o options) *cobra.Command {
	root := &cobra.Command{
		Use:           "keepia-mail",
		Short:         "Keepia Mail: service and command-line tool",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newServeCmd(o),
		newMigrateCmd(o),
		newHealthcheckCmd(),
	)
	return root
}

// exitStatus is the exit code of a command that returned err, and the
// message to print: 0 and nothing on success, 1 and the error otherwise.
func exitStatus(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	return 1, err.Error()
}

// newLogger is the text logger on w at level.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}
