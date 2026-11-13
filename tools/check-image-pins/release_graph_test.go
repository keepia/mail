package main

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// pinnedReleaseConds are the policy's conditions, literally (#77): a bug
// in releaseCondFor changes a string a reviewer reads here. The seven
// explicit ones are the plan's.
var pinnedReleaseConds = map[string]string{
	"version":        "",
	"build":          "",
	"push-rehearsal": "${{ inputs.dry_run }}",
	"push":           "${{ !inputs.dry_run }}",
	"push-arm64":     "${{ !cancelled() && !inputs.dry_run && needs.version.result == 'success' && needs.build.result == 'success' && needs.push.result == 'success' }}",
	"index":          "${{ !cancelled() && !inputs.dry_run && needs.version.result == 'success' && needs.push.result == 'success' && needs.push-arm64.result == 'success' }}",
	"bundle":         "${{ !cancelled() && needs.version.result == 'success' && needs.build.result == 'success' && ((inputs.dry_run && needs.push-rehearsal.result == 'success') || (!inputs.dry_run && needs.push.result == 'success' && needs.push-arm64.result == 'success' && needs.index.result == 'success')) }}",
	"attest":         "${{ !cancelled() && !inputs.dry_run && needs.version.result == 'success' && needs.index.result == 'success' && needs.bundle.result == 'success' }}",
	"attest-assets":  "${{ !cancelled() && !inputs.dry_run && needs.bundle.result == 'success' }}",
	"release":        "${{ !cancelled() && !inputs.dry_run && needs.version.result == 'success' && needs.bundle.result == 'success' && needs.attest.result == 'success' && needs.attest-assets.result == 'success' }}",
	"latest":         "${{ !cancelled() && !inputs.dry_run && needs.version.result == 'success' && needs.index.result == 'success' && needs.release.result == 'success' }}",
}

// TestReleasePolicyConds: the generated conditions are the pinned ones,
// and every job of the policy is in a planned set.
func TestReleasePolicyConds(t *testing.T) {
	if len(releaseJobs) != len(pinnedReleaseConds) || len(releaseJobOrder) != len(releaseJobs) {
		t.Fatalf("%d jobs in the policy, %d in its order, %d pinned", len(releaseJobs), len(releaseJobOrder), len(pinnedReleaseConds))
	}
	for _, j := range releaseJobOrder {
		if got := releaseJobs[j].cond; got != pinnedReleaseConds[j] {
			t.Errorf("job %s: the policy's if is\n  %s\nwant\n  %s", j, got, pinnedReleaseConds[j])
		}
		if releaseJobMode(j) == "" {
			t.Errorf("job %s is in neither planned set", j)
		}
	}
}

// testGraph builds a graph from needs and ifs ("" for no if), in the
// given order.
func testGraph(t *testing.T, order []string, needs map[string][]string, ifs map[string]string) (releaseGraph, map[string]releaseCond) {
	t.Helper()
	g := releaseGraph{order: order, needs: needs, cond: map[string]any{}, line: map[string]int{}}
	conds := map[string]releaseCond{}
	for i, j := range order {
		g.line[j] = i + 1
		if ifs[j] == "" {
			continue
		}
		g.cond[j] = ifs[j]
		c, err := parseReleaseCond(ifs[j], needs[j])
		if err != nil {
			t.Fatalf("job %s: %v", j, err)
		}
		conds[j] = c
	}
	return g, conds
}

func policyGraph(t *testing.T) (releaseGraph, map[string]releaseCond) {
	t.Helper()
	needs := map[string][]string{}
	ifs := map[string]string{}
	for n, j := range releaseJobs {
		needs[n] = j.needs
		ifs[n] = j.cond
	}
	return testGraph(t, releaseJobOrder, needs, ifs)
}

// TestReleasePolicySimulates: the policy runs exactly the planned sets,
// and survives failure injection.
func TestReleasePolicySimulates(t *testing.T) {
	g, conds := policyGraph(t)
	if got := simulateRelease(g, conds, false, ""); !slices.Equal(sortedCopy(got), sortedCopy(releaseRealJobs)) {
		t.Errorf("real run: %v, want %v", got, releaseRealJobs)
	}
	if got := simulateRelease(g, conds, true, ""); !slices.Equal(sortedCopy(got), sortedCopy(releaseDryJobs)) {
		t.Errorf("dry run: %v, want %v", got, releaseDryJobs)
	}
	if p := releaseSimProblems(g, conds); len(p) != 0 {
		t.Errorf("problems: %v", p)
	}
}

// TestReleaseModelMeasuredRuns pins the model against the two measured
// runs on 1f29fb1 (its needs and ifs, inline): real run 43420238830
// attempt 2 ran version, build, push, index and bundle; dry run
// 43419047428 ran version, build, push-rehearsal and bundle.
func TestReleaseModelMeasuredRuns(t *testing.T) {
	order := []string{"version", "build", "push-rehearsal", "push", "index", "bundle", "attest", "attest-assets", "release", "latest"}
	needs := map[string][]string{
		"build":          {"version"},
		"push-rehearsal": {"version", "build"},
		"push":           {"version", "build"},
		"index":          {"version", "push"},
		"bundle":         {"version", "build", "push-rehearsal", "push", "index"},
		"attest":         {"version", "index", "bundle"},
		"attest-assets":  {"bundle"},
		"release":        {"version", "bundle", "attest", "attest-assets"},
		"latest":         {"version", "index", "release"},
	}
	ifs := map[string]string{
		"push-rehearsal": "${{ inputs.dry_run }}",
		"push":           "${{ !inputs.dry_run }}",
		"index":          "${{ !inputs.dry_run }}",
		"bundle":         "${{ !cancelled() && needs.version.result == 'success' && needs.build.result == 'success' && ((inputs.dry_run && needs.push-rehearsal.result == 'success') || (!inputs.dry_run && needs.push.result == 'success' && needs.index.result == 'success')) }}",
		"attest":         "${{ !inputs.dry_run }}",
		"attest-assets":  "${{ !inputs.dry_run }}",
		"release":        "${{ !inputs.dry_run }}",
		"latest":         "${{ !inputs.dry_run }}",
	}
	g, conds := testGraph(t, order, needs, ifs)
	if got, want := simulateRelease(g, conds, false, ""), []string{"version", "build", "push", "index", "bundle"}; !slices.Equal(got, want) {
		t.Errorf("real run: %v, want %v (run 43420238830, attempt 2)", got, want)
	}
	if got, want := simulateRelease(g, conds, true, ""), []string{"version", "build", "push-rehearsal", "bundle"}; !slices.Equal(got, want) {
		t.Errorf("dry run: %v, want %v (run 43419047428)", got, want)
	}
	// Attempt 1: a push row failed, and bundle skipped on its explicit
	// condition.
	if got, want := simulateRelease(g, conds, false, "push"), []string{"version", "build", "push"}; !slices.Equal(got, want) {
		t.Errorf("real run, push failing: %v, want %v (run 43420238830, attempt 1)", got, want)
	}
}

// TestReleaseSemantics: GitHub's rules on synthetic graphs. a runs in a
// dry run only; b runs in both modes after it (!cancelled()); c and the
// others follow b.
func TestReleaseSemantics(t *testing.T) {
	cases := []struct {
		name    string
		bIf     string // "" for always()
		cIf     string
		dry     bool
		failing string
		runs    bool
	}{
		// The attest-assets case: a bare if after a skipped grandparent.
		{"implicit success() behind a skipped grandparent", "", "${{ !inputs.dry_run }}", false, "", false},
		{"no if behind a skipped grandparent", "", "", false, "", false},
		{"!cancelled() with explicit results", "", "${{ !cancelled() && !inputs.dry_run && needs.b.result == 'success' }}", false, "", true},
		{"failure() with a failed grandparent", "", "${{ failure() }}", true, "a", true},
		{"failure() without a failed ancestor", "", "${{ failure() }}", true, "", false},
		{"always() after a failed need", "", "${{ always() }}", true, "b", true},
		{"!cancelled() and no result term after a failed need", "", "${{ !cancelled() }}", true, "b", true},
		{"!cancelled() and no result term after a skipped need", "${{ inputs.dry_run }}", "${{ !cancelled() }}", false, "", true},
		{"a result term after a skipped need", "${{ inputs.dry_run }}", "${{ !cancelled() && needs.b.result == 'success' }}", false, "", false},
		{"a result term after a failed need", "", "${{ !cancelled() && needs.b.result == 'success' }}", true, "b", false},
		{"success() after a failed need", "", "${{ success() }}", true, "b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			order := []string{"a", "b", "c"}
			needs := map[string][]string{"b": {"a"}, "c": {"b"}}
			bIf := c.bIf
			if bIf == "" {
				bIf = "${{ always() }}"
			}
			ifs := map[string]string{"a": "${{ inputs.dry_run }}", "b": bIf, "c": c.cIf}
			g, conds := testGraph(t, order, needs, ifs)
			got := slices.Contains(simulateRelease(g, conds, c.dry, c.failing), "c")
			if got != c.runs {
				t.Errorf("c runs: %v, want %v", got, c.runs)
			}
		})
	}
}

// TestReleaseCondParser: the grammar, fail closed (E-4).
func TestReleaseCondParser(t *testing.T) {
	direct := []string{"x", "y", "push-arm64"}
	accepted := []string{
		"${{ inputs.dry_run }}",
		"!inputs.dry_run",
		// Without a wrapper the whole value is the expression.
		"  !inputs.dry_run\n",
		"${{ !cancelled() && needs.push-arm64.result == 'success' }}",
		"${{ (inputs.dry_run || !inputs.dry_run) && !(needs.x.result == 'success') }}",
		"${{ success() || failure() || always() }}",
	}
	for _, s := range accepted {
		if _, err := parseReleaseCond(s, direct); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	refused := map[string]string{
		"${{ contains(needs.*.result, 'failure') }}":                  `the term "contains"`,
		"${{ github.ref == 'refs/heads/main' }}":                      `the term "github.ref"`,
		"${{ needs.x.result != 'failure' }}":                          "only == 'success'",
		"${{ needs.x.result == 'skipped' }}":                          "only == 'success'",
		"${{ 'success' == needs.x.result }}":                          "a comparison is written needs.<j>.result == 'success'",
		"${{ (inputs.dry_run && needs.x.result == 'success' }}":       "an unbalanced (",
		"${{ inputs.dry_run) }}":                                      `the term ")" after a complete condition`,
		"${{ inputs.version == '' }}":                                 `the term "inputs.version"`,
		"${{ inputs.dry_run == true }}":                               `the term "==" after a complete condition`,
		"${{ needs.z.result == 'success' }}":                          "z is not a direct need",
		"${{ needs.x.outputs.version }}":                              `the term "needs.x.outputs.version"`,
		"${{ !needs.x.result == 'success' }}":                         "negates the result, not the comparison",
		"${{ inputs.dry_run }} && ${{ needs.x.result == 'success' }}": "more than one ${{ }}",
		"${{ inputs.dry_run }} || true":                               "text after the closing }}",
		"always() && ${{ inputs.dry_run }}":                           "text outside the ${{ }}",
		"${{ }}":                                                      "an empty condition",
		"${{ cancelled }}":                                            "cancelled without ()",
		"${{ inputs.dry_run && }}":                                    "the condition ends early",
	}
	// #77 review A, B1: whitespace around the wrapper (a block scalar's
	// trailing newline, a quoted space, Unicode spaces) makes GitHub read
	// the value as a string, which is true.
	for _, s := range []string{
		"  ${{ !cancelled() && needs.push-arm64.result == 'success' }}  ",
		"${{ inputs.dry_run }}\n",
		"${{ inputs.dry_run }} ",
		"\t${{ inputs.dry_run }}",
		" ${{ inputs.dry_run }}",
		"${{ inputs.dry_run }} ",
	} {
		refused[s] = "whitespace around the ${{ }}"
	}
	for s, want := range refused {
		_, err := parseReleaseCond(s, direct)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", s, err, want)
		}
	}
	if _, err := parseReleaseCond(true, direct); err == nil || !strings.Contains(err.Error(), "not a string") {
		t.Errorf("a boolean if: %v", err)
	}
}

// TestReleaseCondPrecedence: ! before && before || (GitHub's order).
func TestReleaseCondPrecedence(t *testing.T) {
	cases := []struct {
		cond string
		dry  bool
		want bool
	}{
		// a || (b && c): true; (a || b) && c would be false.
		{"inputs.dry_run || needs.x.result == 'success' && needs.y.result == 'success'", true, true},
		// (!a) && b: false; !(a && b) would be true.
		{"!inputs.dry_run && needs.x.result == 'success'", true, false},
		// (a && b) || c: true; a && (b || c) would be false.
		{"!inputs.dry_run && needs.x.result == 'success' || inputs.dry_run", true, true},
	}
	for _, c := range cases {
		parsed, err := parseReleaseCond(c.cond, []string{"x", "y"})
		if err != nil {
			t.Fatalf("%q: %v", c.cond, err)
		}
		r := releaseRun{dry: c.dry, result: map[string]string{"x": "failure", "y": "failure"}}
		if got := r.eval("j", parsed.root); got != c.want {
			t.Errorf("%q with dry_run %v: %v, want %v", c.cond, c.dry, got, c.want)
		}
	}
}

// TestReleaseGraphProblems: a cycle and a need that names no job are
// findings, and nothing is simulated then.
func TestReleaseGraphProblems(t *testing.T) {
	cases := map[string]string{
		"jobs:\n  a:\n    needs: b\n  b:\n    needs: [a]\n":      "the needs form a cycle (a -> b -> a)",
		"jobs:\n  a:\n    needs: [a]\n":                          "the needs form a cycle (a -> a)",
		"jobs:\n  a:\n    if: ${{ always() }}\n    needs: [c]\n": `job a: needs "c", which is not a job of release.yml`,
	}
	for src, want := range cases {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
			t.Fatal(err)
		}
		jobs, _ := mappingValue(doc.Content[0], "jobs")
		var got []string
		checkReleaseGraph(jobs, 1, func(_ int, f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) })
		if len(got) != 1 || !strings.Contains(got[0], want) {
			t.Errorf("%q: findings %q, want only %q", src, got, want)
		}
	}
}

// TestReleaseNeedsOrderOnly: reordering a job's needs alone changes
// nothing (P6 compares them as a set; the condition keeps the policy's
// order, E-3).
func TestReleaseNeedsOrderOnly(t *testing.T) {
	root := t.TempDir()
	copyTree(t, releaseFixtureDir, root)
	wf := inJob("release", "    needs: [version, bundle, attest, attest-assets]\n", "    needs: [attest-assets, attest, bundle, version]\n")(t, releaseFixture(t))
	write(t, root, ".github/workflows/release.yml", wf)
	var out, errOut bytes.Buffer
	if code := run([]string{root}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, want 0:\n%s%s", code, out.String(), errOut.String())
	}
}
