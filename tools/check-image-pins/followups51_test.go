package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The #51 part 2 tests that need a file of their own (#84). The Makefile
// GO rows (#51 item 4) are in TestCheckMakefile49, the -verify-pushed
// summaries (#51 items 17-19) in pushed_test.go.

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
