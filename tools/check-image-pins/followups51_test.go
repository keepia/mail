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
		{"GO = go # the go tool", false},
		{"export GO := go # pinned", false},
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
		// The comment of an allowlisted line: " # " and no backslash.
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
