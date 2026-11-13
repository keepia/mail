package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The #51 part 2 tests that need a file of their own (#84). The
// -verify-pushed summaries (#51 items 17-19) are in pushed_test.go.

// TestCheckMakefileGO51 (#51 item 4, PR #91 round 2): GO may be set only
// on an allowlisted line of the raw text; every other text that assigns
// or defines GO is one finding, over-reports included.
func TestCheckMakefileGO51(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		// The allowlist.
		{"GO ?= go", false},
		{"GO        ?= go", false},
		{"GO := go", false},
		{"GO = go", false},
		{"override GO := go", false},
		{"export GO := go", false},
		{"GO?=go", false},
		{"GO\t:=\tgo", false},
		// Not GO, or GO only read.
		{"define GOPROXY_NOTE\ntext\nendef", false},
		{"X_GO = 1", false},
		{"\t$(GO) run ./tools/check-image-pins", false},
		{"\tGOTOOLCHAIN=$$($(GO) env GOVERSION) $(GO) install x@v1", false},
		// #49 and round 1.
		{"GO := ./evil/go", true},
		{"GO := /usr/local/go/bin/go", true},
		{"GO := go -C ./evil", true},
		{"override GO = go -C x", true},
		{"export GO := go -C x", true},
		{"images: GO = go -C x", true},
		{"GO += -C x", true},
		{"GO += go", true},
		{"GO != echo go", true},
		{"define GO\ngo -C ./evil\nendef", true},
		{"define GO\ngo\nendef", true},
		{"override define GO =\ngo\nendef", true},
		{"images-go:\n\t$(eval GO := go -C x)", true},
		{"\techo \"#\"; GO=./evil make images", true},
		// Review A B1: the comment cut.
		{"GO        ?= go\\#||./evil", true},
		{"GO ?= go\\# x", true},
		{"x: ; echo \"#\"; GO=./evil $(MAKE) -f Makefile3 images", true},
		// Review A B2 and review B F1: several assignments on a line.
		{"$(eval GO := go)$(eval GO := ./evil)", true},
		{"$(eval GO := go)\\\n$(eval GO := ./evil)", true},
		{"$(eval GO := go)$(eval GO += -C ./evil)", true},
		{"\t(GO=go); GO=./evil make images", true},
		{"$(eval GO := go) $(eval GO += -C ./evil)", true},
		{"$(eval GO := go) $(eval GO := go -C ./evil)", true},
		// Forms review A found reported, kept so.
		{"GO ::= ./evil", true},
		{"GO :::= ./evil", true},
		{"x: private GO = ./evil", true},
		{"export define GO\ngo\nendef", true},
		{"$(eval GO := $(shell echo go -C x))", true},
		{"MAKEFLAGS += GO=./evil", true},
		{"\t$(MAKE) images GO=./evil", true},
		{"\tenv GO=./evil make images", true},
		// Continuations: make joins them, the allowlist does not.
		{"GO \\\n:= ./evil", true},
		{"GO := go \\\n-C ./evil", true},
		{"GO \\\r\n:= ./evil", true},
		{"FOO = x \\\nGO := go", true},
		{"define \\\nGO\ngo\nendef", true},
		// An allowlisted line takes no comment (review B delta: under
		// .RECIPEPREFIX the line is a recipe and make expands the
		// "comment").
		{"GO = go # $(eval GO := ./evil)", true},
		{"GO = go # the go tool", true},
		{"export GO := go # pinned", true},
		{"GO ?= go #no-space", true},
		{"GO ?= go # a\\b", true},
		// Over-reports, accepted: nothing but the allowlist passes.
		{" GO ?= go", true},
		{"override GO = go", true},
		{"images-go:\n\t$(eval GO := go)", true},
		{"\tGO=go $(MAKE) x", true},
		{"# GO ?= go and an include stay", true},
		{"\t# $(eval GO := ./evil)", true},
		{"GO ?= go\r", true},
		// A function call computes the name (computed-name rule).
		{"$(eval $(firstword GO) := ./evil)", true},
	}
	for _, c := range cases {
		if got := len(CheckMakefile([]byte(c.src+"\n"))) > 0; got != c.want {
			t.Errorf("CheckMakefile(%q) reported %v, want %v", c.src, got, c.want)
		}
	}
	// One finding per line, at the line of the assignment.
	f := CheckMakefile([]byte("GO ?= go\nimages:\n\t$(eval GO := go)$(eval GO := ./evil)\n"))
	if len(f) != 1 || f[0].Line != 3 || !strings.Contains(f[0].Msg, "GO only in a line that is exactly `GO ?= go`") {
		t.Errorf("findings %v, want one at line 3", f)
	}
	// The repository's Makefile passes.
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if f := CheckMakefile(mk); len(f) != 0 {
		t.Errorf("Makefile: %v", f)
	}
}

// TestComposePullPolicy51 (#66 item 9b): rule 4 reports a pull_policy
// key with any value, once per service; the repository's template has
// none.
func TestComposePullPolicy51(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "compose", "fail-pull-policy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := CheckCompose(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"service postgres: pull_policy (always) is not allowed",
		"service memcached: pull_policy (never) is not allowed",
		"service keepia: pull_policy (build) is not allowed",
	}
	if len(f) != len(want) {
		t.Fatalf("findings %v, want %d", f, len(want))
	}
	for i, w := range want {
		if !strings.HasPrefix(f[i].Msg, w) {
			t.Errorf("finding %d is %q, want it to start with %q", i, f[i].Msg, w)
		}
	}

	tmpl, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if f, _, err := CheckCompose(tmpl); err != nil || len(f) != 0 {
		t.Fatalf("docker-compose.yml: findings %v, error %v", f, err)
	}
}

// TestMakefileKnownLimits pins what the Makefile rules do NOT catch
// (maintainer decision on PR #91, 6865260080; the forms of review A
// delta 5898202338). The rules are a fast filter, not a proof: each of
// these reroutes `make images` or a sub-make, and review owns Makefile
// changes (second-review, .claude/rules/docker.md). Each is asserted as
// not reported today, so a rule that starts catching one changes this
// test, and the documented limits in docker.md and index.md, on purpose.
func TestMakefileKnownLimits(t *testing.T) {
	limits := []struct{ name, src string }{
		// `$ ` is the empty one-character variable: the name is built
		// without its text.
		{"computed GO, blank", "G$ O := ./evil"},
		{"computed GO, tab", "G$\tO := ./evil"},
		{"computed GO, continuation", "G$\\\nO := ./evil"},
		{"computed GO, target-specific", "images: G$ O := ./evil"},
		{"computed GO, eval", "$(eval G$ O := ./evil)"},
		{"computed PATH", "PA$ TH := ./evil:$(PATH)"},
		{"computed SHELL", "SHE$ LL := ./evil-sh"},
		// A generated or remade include: make builds gen.mk from a file
		// no Makefile rule reads, then reads it.
		{"generated include", "include gen.mk\ngen.mk: gen.txt\n\tcp gen.txt $@"},
		// A name quoted for a sub-make: the shell removes the quotes.
		{"quoted name for a sub-make", "x:\n\t$(MAKE) -f M6 images G''O=./evil"},
		{"quoted name in MAKEFLAGS", "y:\n\tMAKEFLAGS=G''O=./evil $(MAKE) -f M6 images"},
	}
	for _, c := range limits {
		if f := CheckMakefile([]byte(c.src + "\n")); len(f) != 0 {
			t.Errorf("%s: %q is now reported (%v): update this test and the known limits in docker.md and index.md", c.name, c.src, f)
		}
	}
}
