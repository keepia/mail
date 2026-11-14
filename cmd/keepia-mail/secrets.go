package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/secrets"
)

func newSecretsCmd(o options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Export, restore and show the control secrets",
	}
	cmd.AddCommand(newSecretsExportCmd(o), newSecretsRestoreCmd(o), newSecretsStatusCmd(o))
	return cmd
}

// maxExport bounds what restore reads of an export.
const maxExport = 1 << 20

// errStdinDevice refuses a passphrase from a terminal or any other
// character device, which would echo it (CD25).
var errStdinDevice = errors.New("stdin is a terminal or another device: pipe the passphrase in, for example ./km secrets export < <passphrase-file> > <export-file>")

// passphraseInput checks that stdin is not a device and returns it
// buffered.
func passphraseInput(r io.Reader) (*bufio.Reader, error) {
	if f, ok := r.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
		if fi.Mode()&(os.ModeDevice|os.ModeCharDevice) != 0 {
			return nil, errStdinDevice
		}
	}
	return bufio.NewReader(r), nil
}

// readPassphrase reads the passphrase: stdin's first line, without its
// newline, at most secrets.MaxPassphraseBytes bytes. It is never taken
// from an argument or the environment, which ps and docker inspect show.
func readPassphrase(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		b, err := br.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read the passphrase from stdin: %w", err)
		}
		if b == '\n' {
			break
		}
		line = append(line, b)
		if len(line) > secrets.MaxPassphraseBytes {
			return nil, fmt.Errorf("%w: longer than %d bytes", secrets.ErrPassphrase, secrets.MaxPassphraseBytes)
		}
	}
	return line, secrets.CheckPassphrase(line)
}

func newSecretsExportCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Write the control secrets, sealed under a passphrase read from stdin, to stdout",
		Long: "Reads one passphrase line (16 characters to 1024 bytes) from stdin, which must be a pipe or a file,\n" +
			"and writes the KEK and every sealed secret, encrypted with a key derived by Argon2id, to stdout:\n" +
			"  ./km secrets export < <passphrase-file> > <export-file>\n" +
			"Keep the export and its passphrase apart from this server.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			br, err := passphraseInput(cmd.InOrStdin())
			if err != nil {
				return err
			}
			pass, err := readPassphrase(br)
			if err != nil {
				return err
			}
			if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
				return errors.New("stdin holds more than the passphrase line")
			}
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			if err := secrets.Export(ctx, e.st, e.secretsConfig(), pass, cmd.OutOrStdout()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "control secrets exported: keep the export and its passphrase apart from this server")
			return nil
		},
	}
}

func newSecretsRestoreCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "restore",
		Short: "Restore a missing KEK file from an export: the passphrase line, then the export, on stdin",
		Long: "Reads the passphrase line and then the export from stdin:\n" +
			"  cat <passphrase-file> <export-file> | ./km secrets restore\n" +
			"It writes only the KEK file, and only when it is missing and the database's secrets belong to the export.\n" +
			"It never replaces a KEK and never writes a database row. Restart keepia afterwards.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			br, err := passphraseInput(cmd.InOrStdin())
			if err != nil {
				return err
			}
			pass, err := readPassphrase(br)
			if err != nil {
				return err
			}
			export, err := io.ReadAll(io.LimitReader(br, maxExport+1))
			if err != nil {
				return fmt.Errorf("read the export from stdin: %w", err)
			}
			if len(export) > maxExport {
				return fmt.Errorf("the export on stdin is longer than %d bytes", maxExport)
			}
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			id, err := secrets.Restore(ctx, e.st, e.secretsConfig(), pass, export)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "restored the KEK %s to %s; restart keepia (docker compose restart keepia)\n", id, e.cfg.KEKFile)
			return nil
		},
	}
}

func newSecretsStatusCmd(o options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the control secrets' ids, times and fingerprints (no secret value)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			e, err := openCLI(ctx, o)
			if err != nil {
				return err
			}
			defer e.st.Close()
			s, err := secrets.ReadStatus(ctx, e.st, e.secretsConfig())
			if err != nil {
				return err
			}
			warnUnexported(cmd.ErrOrStderr(), s.LastExportAt != nil, e.cfg.KEKFile)
			_, err = io.WriteString(cmd.OutOrStdout(), s.Text())
			return err
		},
	}
}
