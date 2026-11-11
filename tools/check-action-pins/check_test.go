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

// minFixtures guards against a fixture directory that lost files: the test
// would otherwise pass on whatever is left.
const minFixtures = 54

// TestFixtures runs Check on each fixture in testdata/. A pass-*.yml gives no
// finding and parses. A fail-*.yml gives exactly the lines its first line
// lists (`# want-lines: 8 9`), as a multiset: two findings on one line are
// listed twice. Line 0 stands for "the file does not parse".
func TestFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < minFixtures {
		t.Fatalf("only %d fixtures found, want at least %d", len(files), minFixtures)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yml")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			got := gotLines(src)
			switch {
			case strings.HasPrefix(name, "pass-"):
				if len(got) != 0 {
					t.Errorf("want no finding, got lines %v:\n%s", got, report(src))
				}
			case strings.HasPrefix(name, "fail-"):
				want, ok := wantLines(src)
				if !ok {
					t.Fatalf("first line must be '# want-lines: N ...'")
				}
				if !slices.Equal(got, want) {
					t.Errorf("reported lines %v, want %v:\n%s", got, want, report(src))
				}
			default:
				t.Errorf("fixture name must start with pass- or fail-")
			}
		})
	}
}

// gotLines is the sorted multiset of finding lines; a parse error adds 0.
func gotLines(src []byte) []int {
	findings, err := Check(src)
	var lines []int
	for _, f := range findings {
		lines = append(lines, f.Line)
	}
	if err != nil {
		lines = append(lines, 0)
	}
	slices.Sort(lines)
	return lines
}

func wantLines(src []byte) ([]int, bool) {
	first, _, _ := strings.Cut(string(src), "\n")
	rest, ok := strings.CutPrefix(first, "# want-lines:")
	if !ok {
		return nil, false
	}
	var lines []int
	for _, s := range strings.Fields(rest) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, false
		}
		lines = append(lines, n)
	}
	slices.Sort(lines)
	return lines, len(lines) > 0
}

func report(src []byte) string {
	findings, err := Check(src)
	var b strings.Builder
	for _, f := range findings {
		b.WriteString("  " + f.String() + "\n")
	}
	if err != nil {
		b.WriteString("  parse error: " + err.Error() + "\n")
	}
	return b.String()
}

const (
	pinned   = "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
	unpinned = "      - uses: actions/checkout@v7\n"
	workflow = "name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
	action   = "name: a\ndescription: a\nruns:\n  using: composite\n  steps:\n"
)

// writeTree creates files (path → content) under a new temporary root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestRun covers the exit codes and which files are scanned.
func TestRun(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		want    int
		wantOut string // a substring of stdout, if set
		noRoot  bool
		tooMany bool
	}{
		{name: "missing root", noRoot: true, want: 2},
		{name: "too many arguments", tooMany: true, want: 2},
		{name: "no workflow files", files: map[string]string{"README.md": "x\n"}, want: 2},
		{name: "only an action, no workflow", files: map[string]string{
			".github/actions/x/action.yml": action + pinned,
		}, want: 2},
		{name: "pinned workflow", files: map[string]string{
			".github/workflows/a.yml": workflow + pinned,
		}, want: 0, wantOut: "every uses: is pinned (1 files"},
		{name: "unpinned .yaml workflow", files: map[string]string{
			".github/workflows/a.yml":  workflow + pinned,
			".github/workflows/b.yaml": workflow + unpinned,
		}, want: 1, wantOut: "b.yaml:7: not pinned"},
		{name: "invalid YAML", files: map[string]string{
			".github/workflows/a.yml": workflow + "      - run: echo uses: foo\n",
		}, want: 1, wantOut: "does not parse"},
		{name: "composite action", files: map[string]string{
			".github/workflows/a.yml":      workflow + pinned,
			".github/actions/x/action.yml": action + unpinned,
		}, want: 1, wantOut: filepath.Join(".github", "actions", "x", "action.yml") + ":6: not pinned"},
		{name: "composite action, .yaml", files: map[string]string{
			".github/workflows/a.yml":       workflow + pinned,
			".github/actions/x/action.yaml": action + unpinned,
		}, want: 1, wantOut: "action.yaml:6: not pinned"},
		{name: "nested composite action", files: map[string]string{
			".github/workflows/a.yml":        workflow + pinned,
			".github/actions/a/b/action.yml": action + unpinned,
		}, want: 1, wantOut: filepath.Join("a", "b", "action.yml") + ":6: not pinned"},
		{name: "local action outside .github/actions", files: map[string]string{
			".github/workflows/a.yml": workflow + "      - uses: ./tools/act\n",
			"tools/act/action.yml":    action + unpinned,
		}, want: 1, wantOut: filepath.Join("tools", "act", "action.yml") + ":6: not pinned"},
		{name: "local action that uses another local action", files: map[string]string{
			".github/workflows/a.yml": workflow + "      - uses: ./one\n",
			"one/action.yml":          action + "    - uses: ./two\n",
			"two/action.yaml":         action + unpinned,
		}, want: 1, wantOut: filepath.Join("two", "action.yaml") + ":6: not pinned"},
		{name: "local actions, all pinned", files: map[string]string{
			".github/workflows/a.yml":      workflow + "      - uses: ./tools/act\n      - uses: ./.github/actions/x\n      - uses: ./missing\n      - uses: ./../outside\n",
			"tools/act/action.yml":         action + "    - uses: ./tools/act\n" + strings.TrimPrefix(pinned, "  "),
			".github/actions/x/action.yml": action + strings.TrimPrefix(pinned, "  "),
		}, want: 0, wantOut: "(3 files: 1 workflows, 2 actions)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			switch {
			case tc.noRoot:
				args = []string{filepath.Join(t.TempDir(), "missing")}
			case tc.tooMany:
				args = []string{t.TempDir(), t.TempDir()}
			default:
				args = []string{writeTree(t, tc.files)}
			}
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != tc.want {
				t.Errorf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", got, tc.want, stdout.String(), stderr.String())
			}
			if tc.wantOut != "" && !strings.Contains(stdout.String(), tc.wantOut) {
				t.Errorf("stdout lacks %q:\n%s", tc.wantOut, stdout.String())
			}
		})
	}
}
