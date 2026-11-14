package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/store"
)

// The exit codes of keepia-mail (#95 plan, section 4, with the
// coordinator's ruling CD12). Exit 2 stays the Go runtime's code for a
// panic or a fatal error, so no usage error can pass for a crash.
const (
	exitOK     = 0
	exitFailed = 1  // refused or failed: not found, a rule, a lock timeout, the database
	exitExists = 3  // already exists: lets an import be re-run
	exitUsage  = 64 // EX_USAGE: an unknown command or flag, a wrong argument count, an invalid value
)

// usageError is a usage error: exit 64. Its text is the cause's.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// usagef is a usage error with a formatted text.
func usagef(format string, a ...any) error { return &usageError{fmt.Errorf(format, a...)} }

// exitStatus is the exit code of a command that returned err, and the
// message to print: 0 and nothing on success; 64 for a usage error; 3 for
// a write refused because its row already exists (store.ErrExists); 1 and
// the error otherwise. The message is err's text only: an error of the
// store never carries PostgreSQL's DETAIL, which can quote a row.
func exitStatus(err error) (int, string) {
	if err == nil {
		return exitOK, ""
	}
	var u *usageError
	switch {
	case errors.As(err, &u):
		return exitUsage, err.Error()
	case errors.Is(err, store.ErrExists):
		return exitExists, err.Error()
	}
	return exitFailed, err.Error()
}

// setUsageErrors makes every usage error of root's command tree exit 64:
// an unknown flag or a bad flag value (SetFlagErrorFunc), a wrong number
// of arguments (each command's Args), and an unknown subcommand. A
// command that only groups subcommands, root included, gets Args and RunE
// so that cobra runs it with what it could not match: without them cobra
// prints the help for `keepia-mail mailbox delete x` and exits 0, and
// answers an unknown command of root with a plain error (exit 1).
func setUsageErrors(root *cobra.Command) {
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err} })
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		switch {
		case c.Runnable():
			if args := c.Args; args != nil {
				c.Args = func(cmd *cobra.Command, a []string) error {
					if err := args(cmd, a); err != nil {
						return &usageError{err}
					}
					return nil
				}
			}
		case c.HasSubCommands():
			c.Args = cobra.ArbitraryArgs
			c.RunE = func(cmd *cobra.Command, a []string) error {
				if len(a) > 0 {
					return usagef("unknown command %q for %q", a[0], cmd.CommandPath())
				}
				if !cmd.HasParent() {
					return cmd.Help()
				}
				var names []string
				for _, s := range cmd.Commands() {
					if s.IsAvailableCommand() {
						names = append(names, s.Name())
					}
				}
				return usagef("%s needs a subcommand: %s", cmd.CommandPath(), strings.Join(names, ", "))
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
}
