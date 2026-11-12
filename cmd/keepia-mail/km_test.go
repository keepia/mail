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

// testImage is the image name the fake docker gives for the Compose
// service keepia (`compose ... config --images keepia`).
const testImage = "ghcr.io/keepia/mail:dev"

// fakeDocker sets what the fake docker does: execExit is its exit status
// on `compose ... exec`, imageExit on `image ...` (1: the image is
// missing), and withDockerfile puts a Dockerfile next to km, as in a
// source checkout.
type fakeDocker struct {
	withDockerfile      bool
	execExit, imageExit string
}

// runKm runs a copy of the repository's ./km in a directory of its own,
// with a docker that only logs its arguments, prints testImage on
// `compose ... config` and exits as fake says. It returns km's exit code,
// its output and the docker calls, each as its list of arguments.
func runKm(t *testing.T, fake fakeDocker, args ...string) (int, string, [][]string) {
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
	if fake.withDockerfile {
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "docker.log")
	shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" '" + callEnd + "' >> '" + log + "'\n" +
		"case \"$1 $4\" in\n" +
		"'compose config') echo '" + testImage + "' ;;\n" +
		"'compose exec') exit " + orZero(fake.execExit) + " ;;\n" +
		"'image '*) exit " + orZero(fake.imageExit) + " ;;\n" +
		"esac\nexit 0\n"
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

// orZero returns s, or "0" when s is empty.
func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// imageCheck are the docker calls km makes first: the image name of the
// Compose service keepia, then whether that image is in the local store.
var imageCheck = [][]string{
	{"compose", "--progress", "quiet", "config", "--images", "keepia"},
	{"image", "inspect", testImage},
}

// kmCalls are all docker calls of `./km args...` when the image is there:
// the image check, PostgreSQL and keepia started without building (#56),
// and the command run in the running keepia container.
func kmCalls(args ...string) [][]string {
	return append(slices.Clone(imageCheck),
		[]string{"compose", "--progress", "quiet", "up", "-d", "--wait", "--no-build", "postgres"},
		[]string{"compose", "--progress", "quiet", "up", "-d", "--no-build", "keepia"},
		append([]string{"compose", "--progress", "quiet", "exec", "-T", "keepia", "keepia-mail"}, args...),
	)
}

// ./km migrate checks the image, starts PostgreSQL and keepia, then runs
// the command in the keepia container: exactly these docker calls, with
// every argument passed on as one argument, also one with a space.
func TestKmRunsCommand(t *testing.T) {
	code, out, calls := runKm(t, fakeDocker{}, "migrate", "status", "a b")
	want := kmCalls("migrate", "status", "a b")
	if code != 0 || !slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant:\n%s", code, out, show(calls), show(want))
	}
}

// km exits with the command's exit status.
func TestKmExitStatus(t *testing.T) {
	if code, out, calls := runKm(t, fakeDocker{execExit: "3"}, "migrate"); code != 3 {
		t.Errorf("exit %d, want 3\n%s\ndocker calls:\n%s", code, out, show(calls))
	}
}

// km has no build path, also next to a Dockerfile (a source checkout, as
// in CI): the same calls, none of which builds. Images are built only by
// `make images` or CI's checked bake step (#56, .claude/rules/docker.md).
func TestKmNeverBuilds(t *testing.T) {
	code, out, calls := runKm(t, fakeDocker{withDockerfile: true}, "migrate")
	want := kmCalls("migrate")
	if code != 0 || !slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant:\n%s", code, out, show(calls), show(want))
	}
}

// Without the keepia image, km starts nothing, exits non-zero and names
// `make images`, which builds it.
func TestKmMissingImage(t *testing.T) {
	code, out, calls := runKm(t, fakeDocker{withDockerfile: true, imageExit: "1"}, "migrate")
	if code == 0 || !strings.Contains(out, "make images") || !strings.Contains(out, testImage) ||
		!slices.EqualFunc(calls, imageCheck, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant a non-zero exit, a message with %q and %q, and only:\n%s",
			code, out, show(calls), "make images", testImage, show(imageCheck))
	}
}
