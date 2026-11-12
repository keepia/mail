package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/testwait"
)

// runKm runs a copy of the repository's ./km in a directory of its own,
// with a Dockerfile next to it when withDockerfile is set, and with a
// docker that only logs its arguments and exits runExit on `compose ...
// run`. It returns km's exit code, its output and the docker calls.
func runKm(t *testing.T, withDockerfile bool, runExit string, args ...string) (int, string, []string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
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
	shim := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\n" +
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
	return code, out.String(), strings.Split(strings.TrimSpace(string(data)), "\n")
}

// ./km migrate starts PostgreSQL, then runs the command in a one-off
// keepia container: exactly these two docker calls.
func TestKmRunsCommand(t *testing.T) {
	code, out, calls := runKm(t, false, "0", "migrate", "status")
	want := []string{
		"compose --progress quiet up -d --wait postgres",
		"compose --progress quiet run --rm -T keepia migrate status",
	}
	if code != 0 || strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("exit %d\n%s\ndocker calls:\n%s\nwant:\n%s", code, out, strings.Join(calls, "\n"), strings.Join(want, "\n"))
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
	if want := "compose --progress quiet run --rm --build -T keepia migrate"; code != 0 || calls[len(calls)-1] != want {
		t.Errorf("exit %d\n%s\ndocker calls:\n%s\nwant last: %s", code, out, strings.Join(calls, "\n"), want)
	}
}
