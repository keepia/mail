package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keepia/mail/internal/config"
	"github.com/keepia/mail/internal/password"
	"github.com/keepia/mail/internal/store"
)

// terminal is keepia-mail's standard input as a terminal: whether it is
// one, and a read of one line from it without echo (the password prompt).
// Tests replace it (options.terminal).
type terminal interface {
	IsTerminal() bool
	ReadPassword() ([]byte, error)
}

// stdinTerminal is the process's standard input.
type stdinTerminal struct{}

func (stdinTerminal) IsTerminal() bool { return term.IsTerminal(stdinFD()) }

func (stdinTerminal) ReadPassword() ([]byte, error) { return term.ReadPassword(stdinFD()) }

func stdinFD() int { return int(os.Stdin.Fd()) } //nolint:gosec // a file descriptor fits an int

// stdin is the standard input of the commands: o.stdin, or the process's.
func (o options) input() io.Reader {
	if o.stdin != nil {
		return o.stdin
	}
	return os.Stdin
}

// tty is the terminal seam: o.terminal, or the process's standard input.
func (o options) tty() terminal {
	if o.terminal != nil {
		return o.terminal
	}
	return stdinTerminal{}
}

// maxStdin is the most --password-stdin and --password-hash-stdin read.
const maxStdin = 4096

// readStdin reads r to its end, at most maxStdin bytes, and strips one
// trailing "\n" or "\r\n". Its errors never quote what it read.
func readStdin(r io.Reader, what string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxStdin+1))
	if err != nil {
		return "", fmt.Errorf("read the %s from stdin: %w", what, err)
	}
	if len(data) > maxStdin {
		return "", usagef("the %s on stdin is longer than 4 KiB", what)
	}
	if d, ok := bytes.CutSuffix(data, []byte("\r\n")); ok {
		data = d
	} else {
		data = bytes.TrimSuffix(data, []byte("\n"))
	}
	return string(data), nil
}

// The password flags of mailbox add and mailbox set.
const (
	flagPasswordStdin     = "password-stdin"
	flagPasswordHashStdin = "password-hash-stdin"
)

// passwordInput is what mailbox add or set got for the password: a new
// password, an imported hash, or neither.
type passwordInput struct {
	password, hash string
}

// readPasswordInput reads the password or hash that the flags of cmd ask
// for (#95 plan, section 3), before anything contacts the database. A
// password never comes from argv: there is no --password flag.
//
//   - --password-stdin reads stdin to its end (at most 4 KiB, one trailing
//     newline stripped); if stdin is a terminal, it prompts twice without
//     echo instead, on stderr, and the two entries must be equal.
//   - --password-hash-stdin reads one stored hash the same way (one prompt
//     without echo on a terminal) and validates it (password.ValidateStored).
//   - With neither flag and required set (mailbox add), a terminal gets
//     the prompt; without a terminal it is a usage error.
//
// A password must pass password.Check. Every error is a usage error, and
// none quotes the password or the hash.
func readPasswordInput(cmd *cobra.Command, o options, required bool) (passwordInput, error) {
	f := cmd.Flags()
	pwStdin, hashStdin := f.Changed(flagPasswordStdin), f.Changed(flagPasswordHashStdin)
	if pw, _ := f.GetBool(flagPasswordStdin); pwStdin && !pw {
		pwStdin = false
	}
	if h, _ := f.GetBool(flagPasswordHashStdin); hashStdin && !h {
		hashStdin = false
	}
	tty := o.tty()
	switch {
	case pwStdin && hashStdin:
		return passwordInput{}, usagef("give only one of --%s and --%s", flagPasswordStdin, flagPasswordHashStdin)
	case hashStdin:
		var h string
		var err error
		if tty.IsTerminal() {
			h, err = prompt(cmd, tty, "Password hash: ")
		} else {
			h, err = readStdin(o.input(), "password hash")
		}
		if err != nil {
			return passwordInput{}, err
		}
		if _, err := password.ValidateStored(h); err != nil {
			return passwordInput{}, &usageError{err}
		}
		return passwordInput{hash: h}, nil
	case !pwStdin && !required:
		return passwordInput{}, nil
	}
	var pw string
	switch {
	case tty.IsTerminal():
		first, err := prompt(cmd, tty, "Password: ")
		if err != nil {
			return passwordInput{}, err
		}
		second, err := prompt(cmd, tty, "Repeat the password: ")
		if err != nil {
			return passwordInput{}, err
		}
		if first != second {
			return passwordInput{}, usagef("the two passwords differ")
		}
		pw = first
	case pwStdin:
		var err error
		if pw, err = readStdin(o.input(), "password"); err != nil {
			return passwordInput{}, err
		}
	default:
		return passwordInput{}, usagef("no password: give --%s or --%s, or run on a terminal to be prompted",
			flagPasswordStdin, flagPasswordHashStdin)
	}
	if err := password.Check(pw); err != nil {
		return passwordInput{}, &usageError{err}
	}
	return passwordInput{password: pw}, nil
}

// prompt writes text to stderr and reads one line from the terminal
// without echo.
func prompt(cmd *cobra.Command, tty terminal, text string) (string, error) {
	errOut := cmd.ErrOrStderr()
	fmt.Fprint(errOut, text)
	b, err := tty.ReadPassword()
	fmt.Fprintln(errOut)
	if err != nil {
		return "", fmt.Errorf("read from the terminal: %w", err)
	}
	return string(b), nil
}

// addPasswordFlags adds --password-stdin and --password-hash-stdin.
func addPasswordFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(flagPasswordStdin, false, "read a new password from stdin (for pipes and files; on a terminal it prompts without echo)")
	cmd.Flags().Bool(flagPasswordHashStdin, false, "read a stored password hash to import from stdin ({ARGON2ID}, {BLF-CRYPT}, {SHA512-CRYPT}, {SHA256-CRYPT}, {SSHA}, {SSHA256}, {SSHA512})")
}

// lowerASCII lowercases A-Z only. strings.ToLower would also map
// non-ASCII letters, some of them to ASCII (U+212A KELVIN SIGN to 'k'),
// so that a name the check below refuses could turn into one it accepts.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// The name patterns of the schema (00004_data_model.sql), in Go, so that
// a value is refused with exit 64 before the database is contacted.

// isLabel: ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$.
func isLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// isHost: one or more labels joined by dots, at most 253 characters, not
// only digits and dots.
func isHost(s string) bool {
	if len(s) > 253 || strings.Trim(s, "0123456789.") == "" {
		return false
	}
	for l := range strings.SplitSeq(s, ".") {
		if !isLabel(l) {
			return false
		}
	}
	return true
}

// isDomain: a host of two or more labels.
func isDomain(s string) bool { return strings.Contains(s, ".") && isHost(s) }

// isLocalPart: ^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$ without "..".
func isLocalPart(s string) bool {
	if len(s) < 1 || len(s) > 64 || strings.Contains(s, "..") {
		return false
	}
	end := func(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }
	if !end(s[0]) || !end(s[len(s)-1]) {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !end(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// parseGroup is the group name s, lowercased: a DNS label.
func parseGroup(s string) (string, error) {
	if n := lowerASCII(s); isLabel(n) {
		return n, nil
	}
	return "", usagef("invalid group name %q: want a DNS label (a-z, 0-9 and -, at most 63 characters)", s)
}

// parseDomain is the domain name s, lowercased: two or more DNS labels,
// IDNs as A-labels (xn--...).
func parseDomain(s string) (string, error) {
	if n := lowerASCII(s); isDomain(n) {
		return n, nil
	}
	return "", usagef("invalid domain %q: want two or more DNS labels (a-z, 0-9 and -; IDNs as xn--...), at most 253 characters", s)
}

// parseHost is the host name s (a store's gate name), lowercased.
func parseHost(s string) (string, error) {
	if n := lowerASCII(s); isHost(n) {
		return n, nil
	}
	return "", usagef("invalid store gate name %q: want one or more DNS labels", s)
}

// parseAddress is the mailbox address local@domain, lowercased. With
// domainOnly, @domain (an empty local part) is accepted too: a catch-all
// alias or a send-as grant for a whole domain.
func parseAddress(s string, domainOnly bool) (store.Address, error) {
	local, domain, ok := strings.Cut(lowerASCII(s), "@")
	bad := func() (store.Address, error) {
		want := "local@domain"
		if domainOnly {
			want = "local@domain or @domain"
		}
		return store.Address{}, usagef("invalid address %q: want %s (local part: a-z, 0-9, '.', '_' and '-', at most 64 characters)", s, want)
	}
	if !ok || !isDomain(domain) || (local == "" && !domainOnly) || (local != "" && !isLocalPart(local)) {
		return bad()
	}
	if len(local)+1+len(domain) > 254 {
		return store.Address{}, usagef("invalid address %q: longer than 254 characters", s)
	}
	return store.Address{LocalPart: local, Domain: domain}, nil
}

// The binary units of --quota.
var quotaUnits = []struct {
	name  string
	shift uint
}{{"TiB", 40}, {"GiB", 30}, {"MiB", 20}, {"KiB", 10}}

// parseQuota parses --quota: unlimited or 0 (stored as 0), a number of
// bytes, or a number with KiB, MiB, GiB or TiB, up to 2^63-1 bytes.
func parseQuota(s string) (int64, error) {
	if s == "unlimited" {
		return 0, nil
	}
	num, shift := s, uint(0)
	for _, u := range quotaUnits {
		if n, ok := strings.CutSuffix(s, u.name); ok {
			num, shift = n, u.shift
			break
		}
	}
	bad := usagef("invalid quota %q: want unlimited, 0, a number of bytes, or a number with KiB, MiB, GiB or TiB (at most 2^63-1 bytes)", s)
	if num == "" || strings.Trim(num, "0123456789") != "" {
		return 0, bad
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n > math.MaxInt64>>shift {
		return 0, bad
	}
	return n << shift, nil
}

// formatQuota is a quota as list shows it: unlimited for 0, else in the
// largest unit that divides it exactly (5GiB, 1536MiB, 1000).
func formatQuota(n int64) string {
	if n == 0 {
		return "unlimited"
	}
	for _, u := range quotaUnits {
		if n%(int64(1)<<u.shift) == 0 {
			return strconv.FormatInt(n>>u.shift, 10) + u.name
		}
	}
	return strconv.FormatInt(n, 10)
}

// parseState parses --state: active or disabled.
func parseState(s string) (string, error) {
	if s == store.MailboxActive || s == store.MailboxDisabled {
		return s, nil
	}
	return "", usagef("invalid state %q: want active or disabled", s)
}

// openDataStore opens the store for a data-model command, with the
// database URL from the environment, as migrate does but without
// store.ForMigrations.
func openDataStore(cmd *cobra.Command, o options) (*store.Store, error) {
	dbURL, err := config.Load(os.Getenv).RequireDatabaseURL()
	if err != nil {
		return nil, err
	}
	return store.Open(cmd.Context(), dbURL, o.storeOptions...)
}
