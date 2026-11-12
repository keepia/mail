package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// minFixtures guards against fixture directories that lost files: the test
// would otherwise pass on whatever is left. One pass and one fail fixture
// per rule is the floor; the numbers are the current counts.
var minFixtures = map[string]int{
	"dockerfile": 30,
	"compose":    14,
	"bake":       8,
	"workflow":   8,
}

// fixtureKind maps a testdata directory to the rules its fixtures run.
var fixtureKind = map[string]kind{
	"dockerfile": kindDockerfile,
	"compose":    kindCompose,
	"bake":       kindBake,
	"workflow":   kindWorkflow,
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
						t.Errorf("want no finding, got lines %v:\n%s", got, report(k, src))
					}
				case strings.HasPrefix(name, "fail-"):
					fail++
					want, ok := wantLines(src)
					if !ok {
						t.Fatalf("last line must be '# want-lines: N ...'")
					}
					if !slices.Equal(got, want) {
						t.Errorf("reported lines %v, want %v:\n%s", got, want, report(k, src))
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
	findings, err := checkFile(k, src)
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

func report(k kind, src []byte) string {
	findings, err := checkFile(k, src)
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
		".github/workflows/release.yml": kindNone,
		".github/dependabot.yml":        kindNone,
		"README.md":                     kindNone,
		"tools/x/dockerfile.go":         kindNone,
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
		// Prototypes and testdata are not checked.
		write(t, root, "prototypes/p/Dockerfile", "FROM debian:trixie-slim\n")
		write(t, root, "x/testdata/Dockerfile", "FROM debian:trixie-slim\n")
		var out, errOut bytes.Buffer
		if code := run([]string{root}, &out, &errOut); code != 0 {
			t.Fatalf("exit %d, want 0:\n%s%s", code, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), "1 Dockerfiles") || !strings.Contains(out.String(), "1 workflows") {
			t.Errorf("summary does not count 1 Dockerfile and 1 workflow: %s", out.String())
		}
	})
	t.Run("findings", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "Dockerfile", pinnedSyntaxLine+pinnedFrom)
		write(t, root, "images/a/Dockerfile", pinnedSyntaxLine+"FROM debian:trixie-slim\n")
		write(t, root, "docker-bake.json", "{}\n")
		write(t, root, ".github/workflows/ci.yml", "permissions:\n  packages: write\n")
		write(t, root, "docker-compose.yml", "services: [\n")
		var out, errOut bytes.Buffer
		if code := run([]string{root}, &out, &errOut); code != 1 {
			t.Fatalf("exit %d, want 1:\n%s%s", code, out.String(), errOut.String())
		}
		for _, want := range []string{
			filepath.Join("images", "a", "Dockerfile") + ":2: FROM image",
			"docker-bake.json:0: a JSON bake file",
			filepath.Join(".github", "workflows", "ci.yml") + ":1: workflow grants packages: write",
			"docker-compose.yml: does not parse",
			"4 finding(s) in 5 file(s)",
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
