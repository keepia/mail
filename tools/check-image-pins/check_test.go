package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// minFixtures guards against fixture directories that lost files: the test
// would otherwise pass on whatever is left. The numbers are the current
// counts.
var minFixtures = map[string]int{
	"dockerfile": 33,
	"compose":    19,
	"workflow":   9,
	"repos":      47,
}

// fixtureKind maps a testdata directory of single files to the rules its
// fixtures run. testdata/repos holds whole trees (TestRepos).
var fixtureKind = map[string]kind{
	"dockerfile": kindDockerfile,
	"compose":    kindCompose,
	"workflow":   kindWorkflow,
}

// checkFixture runs the rules of k on one file's source.
func checkFixture(k kind, src []byte) ([]Finding, error) {
	switch k {
	case kindDockerfile:
		return CheckDockerfile(src), nil
	case kindCompose:
		f, _, err := CheckCompose(src)
		return f, err
	case kindWorkflow:
		f, _, err := CheckWorkflow(src, false, nil)
		return f, err
	}
	return nil, nil
}

// TestFixtures runs each rule on its fixtures in testdata/<kind>/. A pass-*
// file gives no finding and parses. A fail-* file gives exactly the lines
// its last line lists (`# want-lines: 3 7`), as a multiset; line 0 stands
// for "the file does not parse" or a whole-file finding. Each directory
// has at least one pass and one fail fixture.
func TestFixtures(t *testing.T) {
	for dir, k := range fixtureKind {
		files, err := filepath.Glob(filepath.Join("testdata", dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < minFixtures[dir] {
			t.Fatalf("%s: only %d fixtures found, want at least %d", dir, len(files), minFixtures[dir])
		}
		var pass, fail int
		for _, f := range files {
			name := filepath.Base(f)
			t.Run(dir+"/"+name, func(t *testing.T) {
				src, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				got := gotLines(k, src)
				switch {
				case strings.HasPrefix(name, "pass-"):
					pass++
					if len(got) != 0 {
						t.Errorf("want no finding, got lines %v:\n%s", got, fixtureReport(k, src))
					}
				case strings.HasPrefix(name, "fail-"):
					fail++
					want, ok := wantLines(src)
					if !ok {
						t.Fatalf("last line must be '# want-lines: N ...'")
					}
					if !slices.Equal(got, want) {
						t.Errorf("reported lines %v, want %v:\n%s", got, want, fixtureReport(k, src))
					}
				default:
					t.Errorf("fixture name must start with pass- or fail-")
				}
			})
		}
		if pass == 0 || fail == 0 {
			t.Errorf("%s: %d pass and %d fail fixtures, want at least one of each", dir, pass, fail)
		}
	}
}

// gotLines is the sorted multiset of finding lines; a parse error adds 0.
func gotLines(k kind, src []byte) []int {
	findings, err := checkFixture(k, src)
	var lines []int
	if err != nil {
		lines = append(lines, 0)
	}
	for _, f := range findings {
		lines = append(lines, f.Line)
	}
	slices.Sort(lines)
	return lines
}

func fixtureReport(k kind, src []byte) string {
	findings, err := checkFixture(k, src)
	var b strings.Builder
	if err != nil {
		b.WriteString("parse error: " + err.Error() + "\n")
	}
	for _, f := range findings {
		b.WriteString(f.String() + "\n")
	}
	return b.String()
}

// wantLines reads the last non-empty line, `# want-lines: N ...`.
func wantLines(src []byte) ([]int, bool) {
	lines := strings.Split(strings.TrimRight(string(src), "\n"), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	rest, ok := strings.CutPrefix(last, "# want-lines:")
	if !ok {
		return nil, false
	}
	var want []int
	for _, w := range strings.Fields(rest) {
		n, err := strconv.Atoi(w)
		if err != nil {
			return nil, false
		}
		want = append(want, n)
	}
	slices.Sort(want)
	return want, len(want) > 0
}

// haveBuildx reports whether `docker buildx` runs. Rule 5 needs it. In CI
// (CI set) its absence fails the test instead of skipping it, so CI never
// passes with the bake fixtures skipped.
func haveBuildx(t *testing.T) bool {
	t.Helper()
	if exec.Command("docker", "buildx", "version").Run() == nil {
		return true
	}
	if os.Getenv("CI") != "" {
		t.Fatal("docker buildx is not available; the bake fixtures need it in CI")
	}
	return false
}

// TestRepos runs the whole check on each tree in testdata/repos/. A
// fixture's WANT file lists one expected output fragment per line: the
// run must print each fragment and report exactly that many findings
// (exit 1). A pass- tree has an empty WANT and must exit 0. Trees with a
// root docker-bake.hcl need docker buildx.
func TestRepos(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "repos", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) < minFixtures["repos"] {
		t.Fatalf("only %d repo fixtures found, want at least %d", len(dirs), minFixtures["repos"])
	}
	buildx := haveBuildx(t)
	for _, dir := range dirs {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(dir, "docker-bake.hcl")); err == nil && !buildx {
				t.Skip("docker buildx is not available")
			}
			raw, err := os.ReadFile(filepath.Join(dir, "WANT"))
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, l := range strings.Split(string(raw), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					want = append(want, l)
				}
			}
			var out, errOut bytes.Buffer
			code := run([]string{dir}, &out, &errOut)
			switch {
			case strings.HasPrefix(name, "pass-"):
				if code != 0 || len(want) != 0 {
					t.Fatalf("exit %d, want 0 (and an empty WANT):\n%s%s", code, out.String(), errOut.String())
				}
			case strings.HasPrefix(name, "fail-"):
				if code != 1 {
					t.Fatalf("exit %d, want 1:\n%s%s", code, out.String(), errOut.String())
				}
				for _, w := range want {
					if !strings.Contains(out.String(), w) {
						t.Errorf("output lacks %q", w)
					}
				}
				if n := strings.Count(out.String(), "\n") - 1; n != len(want) {
					t.Errorf("%d findings, want %d", n, len(want))
				}
				if t.Failed() {
					t.Logf("output:\n%s%s", out.String(), errOut.String())
				}
			default:
				t.Fatalf("fixture name must start with pass- or fail-")
			}
		})
	}
}

// TestBakeWithoutBuildx: without the docker CLI the bake rule cannot
// resolve the definition, and the check fails instead of passing.
func TestBakeWithoutBuildx(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var out, errOut bytes.Buffer
	code := run([]string{filepath.Join("testdata", "repos", "pass-bake")}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "cannot resolve the bake definition") {
		t.Fatalf("exit %d, want 1 with 'cannot resolve the bake definition':\n%s%s", code, out.String(), errOut.String())
	}
}

// TestRepoModeIgnoresCallerEnv: the repository mode resolves the root's
// default files with an explicit --file list in a cleaned environment, so
// neither BUILDX_BAKE_FILE nor a bake variable from the caller changes
// what it checks (review B R1). env-bake.hcl would hide fail-bake-oneline's
// findings, and CTX is irrelevant to it.
func TestRepoModeIgnoresCallerEnv(t *testing.T) {
	if !haveBuildx(t) {
		t.Skip("docker buildx is not available")
	}
	decoy, err := filepath.Abs(filepath.Join("testdata", "env-bake.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUILDX_BAKE_FILE", decoy)
	t.Setenv("CTX", "https://example.invalid/env.git")
	for _, c := range []struct{ repo, want string }{
		// BUILDX_BAKE_FILE would replace the default files.
		{"fail-bake-oneline", `target "b": named contexts`},
		// CTX would be the context of the default resolution; only the
		// sentinel run may set it.
		{"fail-bake-variables", `target "a": context depends on a bake variable`},
	} {
		var out, errOut bytes.Buffer
		code := run([]string{filepath.Join("testdata", "repos", c.repo)}, &out, &errOut)
		if code != 1 || !strings.Contains(out.String(), c.want) || strings.Contains(out.String(), "env.git") {
			t.Errorf("%s: exit %d, want 1 with %q and nothing from the caller's environment:\n%s%s", c.repo, code, c.want, out.String(), errOut.String())
		}
	}
}

// TestBuildMode checks one build's definition: its --set lines and its
// environment are part of what it builds.
func TestBuildMode(t *testing.T) {
	if !haveBuildx(t) {
		t.Skip("docker buildx is not available")
	}
	repo := filepath.Join("testdata", "repos", "pass-bake")
	// The job's PLATFORM gives the cache scope build mode allows.
	t.Setenv("PLATFORM", "linux/amd64")
	cases := []struct {
		name, targets, sets, env string
		code                     int
		want                     string
	}{
		{"clean", "a", "a.cache-from=type=gha,scope=a-amd64\na.cache-to=", "", 0, "build a resolves to pinned images"},
		// Review A delta 2, 1a: a foreign cache stands in for build steps.
		{"registry cache", "a", "a.cache-from=type=registry,ref=registry.invalid/attacker/cache:latest", "", 1, `cache-from map[ref:registry.invalid/attacker/cache:latest type:registry] is not allowed`},
		{"other scope", "a", "a.cache-to=type=gha,scope=root-amd64,mode=max", "", 1, "only type=gha with scope=a-amd64"},
		{"gha with url", "a", "a.cache-from=type=gha,scope=a-amd64,url=https://example.invalid/", "", 1, "no other key"},
		{"set output", "a", "a.output=type=local,dest=/tmp/x", "", 1, `target "a": output is not allowed`},
		{"set network", "a", "a.network=host", "", 1, `network "host" is not allowed here`},
		{"set contexts", "a", "a.contexts.base=docker-image://busybox:latest", "", 1, `target "a": named contexts are not allowed`},
		{"set syntax", "root", "*.args.BUILDKIT_SYNTAX=docker/dockerfile:latest", "", 1, `target "root": the BUILDKIT_SYNTAX argument`},
		{"env file", "a", "", "env-bake.hcl", 1, `target "a": context "https://example.invalid/env.git"`},
		{"injected name", "--file=x.hcl", "", "", 1, `target name "--file=x.hcl" is not a plain name`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.env != "" {
				p, err := filepath.Abs(filepath.Join("testdata", c.env))
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("BUILDX_BAKE_FILE", p)
			}
			var out, errOut bytes.Buffer
			code := run([]string{"-build", c.targets, "-build-set", c.sets, repo}, &out, &errOut)
			if code != c.code || !strings.Contains(out.String(), c.want) {
				t.Fatalf("exit %d, want %d with %q:\n%s%s", code, c.code, c.want, out.String(), errOut.String())
			}
		})
	}
}

// TestBakeLocal: local mode resolves and checks exactly the argv and
// environment it will build with, takes only typed options, and
// ignores the caller's BUILDX_* and bake variables (review B delta 2:
// V1 adds --file through a make variable, V5 exports BUILDX_BAKE_FILE).
func TestBakeLocal(t *testing.T) {
	if !haveBuildx(t) {
		t.Skip("docker buildx is not available")
	}
	repo := filepath.Join("testdata", "repos", "pass-bake")
	decoy, err := filepath.Abs(filepath.Join("testdata", "env-bake.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := filepath.Abs(filepath.Join("testdata", "env-bake.hcl")) // any readable file
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		env  map[string]string
		code int
		want string
	}{
		{"clean", []string{"-root", repo, "-dry-run", "-version", "1.0.0"}, nil, 0, " buildx bake --file docker-bake.hcl --load -- default"},
		{"proxy options", []string{"-root", repo, "-dry-run", "-ca", ca, "-host-network", "-https-proxy", "http://127.0.0.1:3128"}, nil, 0,
			"--allow network.host --set *.secrets=id=ca,src=" + ca + " --set *.network=host --set *.args.HTTPS_PROXY=http://127.0.0.1:3128 --load -- default"},
		// V1: a free --file is not an option of the tool.
		{"free --file", []string{"-root", repo, "-dry-run", "--file=m.txt"}, nil, 2, ""},
		// V5 and caller variables: not passed to bake.
		{"caller env", []string{"-root", repo, "-dry-run", "a"}, map[string]string{"BUILDX_BAKE_FILE": decoy, "CTX": "https://example.invalid/env.git"}, 0, "--load -- a"},
		{"bad proxy", []string{"-root", repo, "-dry-run", "-https-proxy", "http://x,y"}, nil, 1, `-https-proxy "http://x,y" is not http(s)://host[:port]`},
		{"bad target", []string{"-root", repo, "-dry-run", "--", "-x"}, nil, 1, `target name "-x" is not a plain name`},
		{"bad version", []string{"-root", repo, "-dry-run", "-version", "1 --file=x"}, nil, 1, `-version "1 --file=x" has characters outside`},
		{"bake options outside local mode", []string{"-ca", ca}, nil, 2, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			var out, errOut bytes.Buffer
			code := run(append([]string{"-bake-local"}, c.args...), &out, &errOut)
			if c.name == "bake options outside local mode" {
				code = run(c.args, &out, &errOut)
			}
			if code != c.code || !strings.Contains(out.String(), c.want) || strings.Contains(out.String(), "env.git") {
				t.Fatalf("exit %d, want %d with %q:\n%s%s", code, c.code, c.want, out.String(), errOut.String())
			}
		})
	}
}

// TestVerifyBuilt: the images a job tests and saves must be the checked
// build's output (review B delta 2, D2).
func TestVerifyBuilt(t *testing.T) {
	const d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const c1 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	const other = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	meta := `{"buildx.build.warnings":[],"postfix":{"image.name":"ghcr.io/keepia/mail-postfix:dev,ghcr.io/keepia/mail-postfix:x","containerimage.digest":"` + d1 + `","containerimage.config.digest":"` + c1 + `"}}`
	cases := []struct {
		name     string
		meta     string
		ids      map[string]string
		findings int
		want     string
	}{
		{"manifest digest (containerd store)", meta, map[string]string{"ghcr.io/keepia/mail-postfix:dev": d1, "ghcr.io/keepia/mail-postfix:x": d1}, 0, ""},
		{"config digest (classic store)", meta, map[string]string{"ghcr.io/keepia/mail-postfix:dev": c1, "ghcr.io/keepia/mail-postfix:x": c1}, 0, ""},
		// W1: another build or a docker tag replaced one name.
		{"replaced", meta, map[string]string{"ghcr.io/keepia/mail-postfix:dev": other, "ghcr.io/keepia/mail-postfix:x": d1}, 1, "it was replaced after the build"},
		{"missing", meta, map[string]string{"ghcr.io/keepia/mail-postfix:x": d1}, 1, "is not in the local store"},
		{"no image", `{"postfix":{}}`, nil, 1, "names no image or digest"},
		{"empty", `{}`, nil, 1, "names no image"},
		{"not JSON", `nope`, nil, 1, "does not parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inspect := func(name string) (string, error) {
				id, ok := c.ids[name]
				if !ok {
					return "", os.ErrNotExist
				}
				return id, nil
			}
			findings, _, _ := verifyBuilt([]byte(c.meta), inspect)
			if len(findings) != c.findings || (c.want != "" && !strings.Contains(strings.Join(findings, "\n"), c.want)) {
				t.Fatalf("findings %q, want %d with %q", findings, c.findings, c.want)
			}
		})
	}
	t.Run("no metadata", func(t *testing.T) {
		t.Setenv("BAKE_METADATA", "")
		var out, errOut bytes.Buffer
		if code := run([]string{"-verify-built"}, &out, &errOut); code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out.String())
		}
	})
}

// TestClassify checks which files the walk checks, and as what.
func TestClassify(t *testing.T) {
	cases := map[string]kind{
		"Dockerfile":                    kindDockerfile,
		"images/postfix/Dockerfile":     kindDockerfile,
		"images/x/Dockerfile.test":      kindDockerfile,
		"images/x/build.Dockerfile":     kindDockerfile,
		"Containerfile":                 kindDockerfile,
		"docker-compose.yml":            kindCompose,
		"compose.override.yaml":         kindCompose,
		"docker-bake.hcl":               kindBake,
		"docker-bake.override.hcl":      kindBake,
		"docker-bake.json":              kindBakeJSON,
		".github/workflows/ci.yml":      kindWorkflow,
		".github/workflows/x.yaml":      kindWorkflow,
		".github/workflows/release.yml": kindReleaseWorkflow,
		".github/dependabot.yml":        kindNone,
		"README.md":                     kindNone,
		"tools/x/dockerfile.go":         kindNone,
		"build/docker-bake.hcl":         kindStrayHCL,
		"images.hcl":                    kindStrayHCL,
		"Makefile":                      kindMakefile,
		"tools/x.mk":                    kindMakefile,
		"scripts/build.sh":              kindScript,
	}
	for rel, want := range cases {
		if got := classify(filepath.FromSlash(rel)); got != want {
			t.Errorf("classify(%s) = %d, want %d", rel, got, want)
		}
	}
}

const pinnedFrom = "FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2\n"
const pinnedSyntaxLine = "# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183\n"

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRun checks the walk: what it reports, what it skips, and its exit
// codes.
func TestRun(t *testing.T) {
	t.Run("clean tree", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "Dockerfile", pinnedSyntaxLine+pinnedFrom)
		write(t, root, ".github/workflows/ci.yml", "permissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n")
		// release.yml may push packages.
		write(t, root, ".github/workflows/release.yml", "permissions:\n  packages: write\n")
		// The root's prototypes and the check fixtures are not walked.
		write(t, root, "prototypes/p/Dockerfile", "FROM debian:trixie-slim\n")
		write(t, root, "tools/check-image-pins/testdata/Dockerfile", "FROM debian:trixie-slim\n")
		var out, errOut bytes.Buffer
		if code := run([]string{root}, &out, &errOut); code != 0 {
			t.Fatalf("exit %d, want 0:\n%s%s", code, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), "1 Dockerfiles") || !strings.Contains(out.String(), "2 workflows") {
			t.Errorf("summary does not count 1 Dockerfile and 2 workflows: %s", out.String())
		}
	})
	t.Run("findings", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "Dockerfile", pinnedSyntaxLine+pinnedFrom)
		write(t, root, "images/a/Dockerfile", pinnedSyntaxLine+"FROM debian:trixie-slim\n")
		write(t, root, "docker-bake.json", "{}\n")
		write(t, root, ".github/workflows/ci.yml", "permissions:\n  packages: write\n")
		// release.yml may push, but its job images are pinned too.
		write(t, root, ".github/workflows/release.yml", "permissions:\n  packages: write\njobs:\n  a:\n    container: node:20\n")
		write(t, root, "docker-compose.yml", "services: [\n")
		var out, errOut bytes.Buffer
		if code := run([]string{root}, &out, &errOut); code != 1 {
			t.Fatalf("exit %d, want 1:\n%s%s", code, out.String(), errOut.String())
		}
		for _, want := range []string{
			filepath.Join("images", "a", "Dockerfile") + ":2: FROM image",
			"docker-bake.json:0: a JSON bake file",
			filepath.Join(".github", "workflows", "ci.yml") + ":1: workflow grants packages: write",
			filepath.Join(".github", "workflows", "release.yml") + ":4: job a: container image \"node:20\"",
			"docker-compose.yml:0: does not parse",
			// bake reads the root's default files, the broken Compose file
			// included, and the check reports that it cannot resolve them.
			"docker-compose.yml,docker-bake.json:0: cannot resolve the bake definition",
			"6 finding(s)",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("output lacks %q:\n%s", want, out.String())
			}
		}
	})
	t.Run("no Dockerfile", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run([]string{t.TempDir()}, &out, &errOut); code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
	})
	t.Run("usage", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run([]string{"a", "b"}, &out, &errOut); code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
		if code := run([]string{filepath.Join(t.TempDir(), "missing")}, &out, &errOut); code != 2 {
			t.Errorf("missing root: exit %d, want 2", code)
		}
	})
}

// TestPinnedImage covers the reference grammar beyond the fixtures.
func TestPinnedImage(t *testing.T) {
	const d = "@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	good := []string{
		"debian:trixie-slim" + d,
		"gcr.io/distroless/static-debian13:nonroot" + d,
		"localhost:5000/a/b:1.0" + d,
		"registry.example.org:5000/team/app:v1.2.3" + d,
		"docker/dockerfile:1.29.0" + d,
	}
	bad := []string{
		"debian" + d,                             // no tag
		"debian:trixie-slim",                     // no digest
		"debian:trixie-slim@sha256:a72b4433de1c", // short digest
		"Debian:trixie" + d,                      // uppercase name
		"debian:trixie" + d + " ",                // trailing space
		"debian:trixie@sha512:" + strings.Repeat("a", 128),
		"${BASE}:x" + d,
	}
	for _, s := range good {
		if !isPinnedImage(s) {
			t.Errorf("isPinnedImage(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if isPinnedImage(s) {
			t.Errorf("isPinnedImage(%q) = true, want false", s)
		}
	}
}
