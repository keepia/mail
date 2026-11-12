package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/testwait"
)

// callEnd ends each docker call in the shim's log; the shim writes every
// argument on a line of its own, so argument boundaries are kept.
const callEnd = "--end-of-call--"

// runKm runs a copy of the repository's ./km in a directory of its own,
// with a Dockerfile next to it when withDockerfile is set, and with a
// docker that only logs its arguments and exits runExit on `compose ...
// run`. It returns km's exit code, its output and the docker calls, each
// as its list of arguments.
func runKm(t *testing.T, withDockerfile bool, runExit string, args ...string) (int, string, [][]string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		// CI must run these tests, never skip them.
		if os.Getenv("CI") != "" {
			t.Fatal("no sh in CI: the km tests must run there")
		}
		t.Skip("no sh")
	}
	src, err := os.ReadFile("../../km")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	km := filepath.Join(dir, "km")
	if err := os.WriteFile(km, src, 0o700); err != nil { //nolint:gosec // an executable copy of the script
		t.Fatal(err)
	}
	if withDockerfile {
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "docker.log")
	shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" '" + callEnd + "' >> '" + log + "'\n" +
		"if [ \"$4\" = run ]; then exit " + runExit + "; fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0o700); err != nil { //nolint:gosec // an executable test script
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Limit(t))
	defer cancel()
	cmd := exec.CommandContext(ctx, km, args...) //nolint:gosec // a copy of the repository's own script
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	data, _ := os.ReadFile(log)
	var calls [][]string
	var call []string
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSuffix(line, "\n")
		if line == callEnd {
			calls = append(calls, call)
			call = nil
			continue
		}
		call = append(call, line)
	}
	return code, out.String(), calls
}

// show formats docker calls for a failure message, one call per line,
// each argument quoted.
func show(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		fmt.Fprintf(&b, "%q\n", c)
	}
	return b.String()
}

// ./km migrate starts PostgreSQL, then runs the command in a one-off
// keepia container: exactly these two docker calls, with every argument
// passed on as one argument, also one with a space.
func TestKmRunsCommand(t *testing.T) {
	code, out, calls := runKm(t, false, "0", "migrate", "status", "a b")
	want := [][]string{
		{"compose", "--progress", "quiet", "up", "-d", "--wait", "postgres"},
		{"compose", "--progress", "quiet", "run", "--rm", "-T", "keepia", "migrate", "status", "a b"},
	}
	if code != 0 || !slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant:\n%s", code, out, show(calls), show(want))
	}
}

// km exits with the command's exit status.
func TestKmExitStatus(t *testing.T) {
	if code, out, _ := runKm(t, false, "3", "migrate"); code != 3 {
		t.Errorf("exit %d, want 3\n%s", code, out)
	}
}

// Next to a Dockerfile, km rebuilds the image.
func TestKmBuildsNextToDockerfile(t *testing.T) {
	code, out, calls := runKm(t, true, "0", "migrate")
	want := []string{"compose", "--progress", "quiet", "run", "--rm", "--build", "-T", "keepia", "migrate"}
	if code != 0 || len(calls) == 0 || !slices.Equal(calls[len(calls)-1], want) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant last: %q", code, out, show(calls), want)
	}
}
