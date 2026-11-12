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
	"strconv"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/testwait"
)

// callEnd ends each docker call in the shim's log; the shim writes every
// argument on a line of its own, so argument boundaries are kept.
const callEnd = "--end-of-call--"

// Image names the fake docker prints for `compose ... config --images
// postgres keepia`: Compose lists the services' own images and those of
// the services they depend on (#57, B1, B3).
const (
	testImage = "registry.example.org/keepia/mail:dev"
	testDep   = "registry.example.org/keepia/mail-dep:dev"
	// testPinned is an upstream image pinned by digest, which km pulls by
	// that digest when it is missing.
	testPinned = "registry.example.org/library/postgres:18@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// fakeDocker sets what the fake docker does: images are the lines it
// prints on `compose ... config` (default: testImage, testDep and
// testPinned), `image ...` exits 1 when an argument is one of missing,
// pullExit is its exit status on `pull`, execExit on `compose ... exec`,
// withDockerfile puts a Dockerfile next to km, as in a source checkout,
// and noDaemon fails every call that needs a Docker daemon with a
// connection error. execOut is what `compose ... exec` prints on stderr,
// and trace runs km as `PS4='+ ' sh -x km`, as test 7's counter-case does.
type fakeDocker struct {
	withDockerfile     bool
	noDaemon           bool
	trace              bool
	images, missing    []string
	pullExit, execExit string
	execOut            string
}

// imageList returns the images the fake prints.
func (f fakeDocker) imageList() []string {
	if f.images == nil {
		return []string{testImage, testDep, testPinned}
	}
	return f.images
}

// runKm runs a copy of the repository's ./km in a directory of its own,
// with a docker that only logs its arguments and answers as fake says.
// It returns km's exit code, its output and the docker calls, each as its
// list of arguments.
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
	missing := "''"
	if len(fake.missing) > 0 {
		missing = "'" + strings.Join(fake.missing, "'|'") + "'"
	}
	noDaemon := ""
	if fake.noDaemon {
		// As with a real docker: every call that needs the daemon fails
		// with a connection error; `compose config` needs none.
		noDaemon = "case \"$1 $4\" in 'compose config') ;; *)\n" +
			"\techo 'failed to connect to the docker API at unix:///var/run/docker.sock' >&2; exit 1 ;; esac\n"
	}
	shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" '" + callEnd + "' >> '" + log + "'\n" + noDaemon +
		"if [ \"$1\" = image ]; then\n" +
		"\tfor a; do case $a in " + missing + ") exit 1 ;; esac; done\n" +
		"\texit 0\nfi\n" +
		"if [ \"$1\" = pull ] && [ " + orZero(fake.pullExit) + " != 0 ]; then\n" +
		"\techo 'Error response from daemon: manifest unknown' >&2; exit " + orZero(fake.pullExit) + "\nfi\n" +
		"case \"$1 $4\" in\n" +
		"'compose config') printf '%s\\n' '" + strings.Join(fake.imageList(), "' '") + "' ;;\n" +
		"'compose exec') [ -n \"$FAKE_EXEC_OUT\" ] && printf '%s\\n' \"$FAKE_EXEC_OUT\" >&2; exit " + orZero(fake.execExit) + " ;;\n" +
		"esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0o700); err != nil { //nolint:gosec // an executable test script
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Limit(t))
	defer cancel()
	cmd := exec.CommandContext(ctx, km, args...) //nolint:gosec // a copy of the repository's own script
	if fake.trace {
		cmd = exec.CommandContext(ctx, "sh", append([]string{"-x", km}, args...)...) //nolint:gosec // a copy of the repository's own script
	}
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"PS4=+ ", "FAKE_EXEC_OUT="+fake.execOut)
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

// daemonCheck is km's first docker call: is the Docker daemon reachable.
var daemonCheck = []string{"version", "--format", "{{.Server.Version}}"}

// inspect and pull are the docker calls that check whether an image is
// in the local store and pull an image pinned by digest.
func inspect(image string) []string { return []string{"image", "inspect", "--", image} }
func pull(image string) []string    { return []string{"pull", "-q", "--", image} }

// imageCheck are the docker calls km makes first: the daemon check, the
// images of the Compose services postgres and keepia and the services
// they depend on, then the given calls of the image loop.
func imageCheck(loop ...[]string) [][]string {
	return append([][]string{daemonCheck, {"compose", "--progress", "quiet", "config", "--images", "postgres", "keepia"}}, loop...)
}

// allPresent are the loop's calls when the default images are all in the
// local store: one inspect each, no pull.
var allPresent = [][]string{inspect(testImage), inspect(testDep), inspect(testPinned)}

// kmCalls are all docker calls of `./km args...` after the given calls of
// the image loop: PostgreSQL and keepia started without building (#56)
// and without pulling (#57, B2, B3), and the command run in the running
// keepia container.
func kmCalls(loop [][]string, args ...string) [][]string {
	return append(imageCheck(loop...),
		[]string{"compose", "--progress", "quiet", "up", "-d", "--wait", "--no-build", "--pull", "never", "postgres"},
		[]string{"compose", "--progress", "quiet", "up", "-d", "--no-build", "--pull", "never", "keepia"},
		append([]string{"compose", "--progress", "quiet", "exec", "-T", "keepia", "keepia-mail"}, args...),
	)
}

// ./km migrate checks every image, starts PostgreSQL and keepia, then
// runs the command in the keepia container: exactly these docker calls,
// with every argument passed on as one argument, also one with a space.
func TestKmRunsCommand(t *testing.T) {
	code, out, calls := runKm(t, fakeDocker{}, "migrate", "status", "a b")
	want := kmCalls(allPresent, "migrate", "status", "a b")
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
	want := kmCalls(allPresent, "migrate")
	if code != 0 || !slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant:\n%s", code, out, show(calls), show(want))
	}
}

// When an image is missing, here that of a service keepia depends on (the
// second line of `config --images`), km starts nothing, exits non-zero,
// and names the image and `make images`, which builds it.
func TestKmMissingImage(t *testing.T) {
	code, out, calls := runKm(t, fakeDocker{withDockerfile: true, missing: []string{testDep}}, "migrate")
	want := imageCheck(inspect(testImage), inspect(testDep))
	if code == 0 || !strings.Contains(out, "make images") || !strings.Contains(out, testDep) ||
		!strings.Contains(out, "(Compose service postgres or keepia, or a service they depend on)") ||
		!slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant a non-zero exit, a message with %q and %q, and only:\n%s",
			code, out, show(calls), "make images", testDep, show(want))
	}
}

// A missing upstream image pinned by digest is pulled by that digest
// (content-addressed) before anything starts, since both ups are
// --pull never (#57, B3).
func TestKmPullsPinnedImage(t *testing.T) {
	fake := fakeDocker{missing: []string{testPinned}}
	code, out, calls := runKm(t, fake, "migrate")
	want := kmCalls(append(slices.Clone(allPresent), pull(testPinned)), "migrate")
	if code != 0 || !slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant:\n%s", code, out, show(calls), show(want))
	}
}

// If that pull fails, km starts nothing, exits non-zero, and shows
// docker's error and the image; it does not name `make images`.
func TestKmPinnedPullFails(t *testing.T) {
	fake := fakeDocker{missing: []string{testPinned}, pullExit: "1"}
	code, out, calls := runKm(t, fake, "migrate")
	want := imageCheck(append(slices.Clone(allPresent), pull(testPinned))...)
	if code == 0 || !strings.Contains(out, "manifest unknown") || !strings.Contains(out, testPinned) ||
		strings.Contains(out, "make images") || !slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant a non-zero exit, docker's error, %q, no %q, and only:\n%s",
			code, out, show(calls), testPinned, "make images", show(want))
	}
}

// Without a reachable Docker daemon, km stops with docker's own error and
// does not claim that an image is missing.
func TestKmNoDaemon(t *testing.T) {
	code, out, calls := runKm(t, fakeDocker{noDaemon: true}, "migrate")
	want := [][]string{daemonCheck}
	if code == 0 || strings.Contains(out, "make images") || !strings.Contains(out, "failed to connect") ||
		!slices.EqualFunc(calls, want, slices.Equal) {
		t.Errorf("exit %d\n%s\ndocker calls:\n%swant a non-zero exit, docker's error, no %q, and only:\n%s",
			code, out, show(calls), "make images", show(want))
	}
}

// Test 7's counter-case (#69) runs `PS4='+ ' sh -x ./km migrate status`
// and gives its exit status and output to scripts/km-failure-cause.sh,
// which accepts a failure only at km's exec, found by its traced exec
// line. Here the real km, traced, with a fake docker: the exec's answers
// to a crash-looping keepia are accepted, every other failure is not.
func TestKmFailureCause(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		fake fakeDocker
		ok   bool
	}{
		{"exec found keepia restarting", fakeDocker{execExit: "1",
			execOut: "Error response from daemon: Container " + id + " is restarting, wait until the container is running"}, true},
		{"exec met the exit of keepia's run", fakeDocker{execExit: "128",
			execOut: "OCI runtime exec failed: exec failed: cannot exec in a stopped container"}, true},
		{"migrate killed with keepia's run", fakeDocker{execExit: "137"}, true},
		{"migrate's own login failed", fakeDocker{execExit: "1",
			execOut: `error: connect to database: failed SASL auth: FATAL: password authentication failed for user "keepia" (SQLSTATE 28P01)`}, true},
		{"migrate failed for another reason", fakeDocker{execExit: "1",
			execOut: "error: connect to database: dial tcp 172.29.1.11:5432: connect: connection refused"}, false},
		{"km succeeded", fakeDocker{}, false},
		{"no daemon", fakeDocker{noDaemon: true}, false},
		{"image missing", fakeDocker{missing: []string{testDep}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.fake.trace = true
			code, out, _ := runKm(t, c.fake, "migrate", "status")
			ctx, cancel := context.WithTimeout(context.Background(), testwait.Limit(t))
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "../../scripts/km-failure-cause.sh", strconv.Itoa(code), out)
			verdict, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if err != nil && !errors.As(err, &exit) {
				t.Fatal(err)
			}
			if got := err == nil; got != c.ok {
				t.Errorf("accepted %v, want %v: %s\nkm exited %d:\n%s", got, c.ok, verdict, code, out)
			}
		})
	}
}
