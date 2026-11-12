package main

import (
	"slices"
	"strings"
	"testing"
)

// TestReferencedTexts: each way of running a script of #49 point 1
// resolves to the script, as a text that runs; a path the check cannot
// resolve is a problem instead.
func TestReferencedTexts(t *testing.T) {
	root := t.TempDir()
	write(t, root, "scripts/save.sh", "docker save x -o x.tar\n")
	write(t, root, "scripts/ci.sh", "sh \"$(dirname \"$0\")/save.sh\"\n")
	write(t, root, "scripts/top.sh", "sh \"$(cd \"$(dirname -- \"${BASH_SOURCE[0]}\")\" && pwd)/save.sh\"\n")
	write(t, root, "Makefile", "SCRIPTS := scripts\nall: pre\n\t@echo default\npre:\n\tsh $(SCRIPTS)/save.sh\nother:\n\t$(MAKE) pre\n")
	write(t, root, ".github/actions/outer/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n")
	write(t, root, ".github/actions/inner/action.yml", "runs:\n  using: composite\n  steps:\n    - shell: bash\n      working-directory: scripts\n      run: ./save.sh\n")
	cases := []struct {
		text, workdir string
		want          string // a path among the texts that run, or a problem
	}{
		{`bash "$GITHUB_WORKSPACE/scripts/save.sh"`, "", "scripts/save.sh"},
		{`bash "${GITHUB_WORKSPACE}/scripts/save.sh"`, "", "scripts/save.sh"},
		{`bash ${{ github.workspace }}/scripts/save.sh`, "", "scripts/save.sh"},
		{`./save.sh`, "scripts", "scripts/save.sh"},
		{`./save.sh`, "${{ github.workspace }}/scripts", "scripts/save.sh"},
		{`cd scripts && sh save.sh`, "", "scripts/save.sh"},
		{`sudo -E env A=1 bash -e scripts/ci.sh`, "", "scripts/save.sh"},
		{`sh scripts/top.sh`, "", "scripts/save.sh"},
		{`bash -c 'sh scripts/save.sh'`, "", "scripts/save.sh"},
		{`. scripts/save.sh`, "", "scripts/save.sh"},
		{`make pre`, "", "Makefile (make pre)"},
		{`make`, "", "Makefile (make all)"},
		{`make -C . other`, "", "scripts/save.sh"},
		{`./.github/actions/outer`, "", ".github/actions/inner/action.yml"},
		{`sh "$SCRIPT"`, "", "problem: it runs $SCRIPT"},
		{`bash /tmp/x.sh`, "", "problem: it runs /tmp/x.sh"},
		{`sh "$(mktemp)"`, "", "problem: it runs $(mktemp)"},
		{`sh scripts/missing.sh`, "", "problem: it runs scripts/missing.sh"},
		{`make missing`, "", "problem: it runs make missing, which has no explicit rule"},
		{`make -C nowhere`, "", "problem: it runs make -C nowhere"},
		{`./save.sh`, "$DIR", "problem: its working-directory"},
	}
	for _, c := range cases {
		texts, problems := referencedTexts(root, c.text, c.workdir, true)
		var got []string
		for _, tx := range texts {
			if tx.exec {
				got = append(got, tx.path)
			}
		}
		for _, p := range problems {
			got = append(got, "problem: "+p)
		}
		if !slices.ContainsFunc(got, func(g string) bool { return strings.HasPrefix(g, c.want) }) {
			t.Errorf("referencedTexts(%q, workdir %q) = %q, want %q", c.text, c.workdir, got, c.want)
		}
	}
	// Controls: commands on PATH, system paths and arguments are not
	// problems.
	for _, text := range []string{
		`go run ./tools/check-image-pins -verify-built`,
		`/usr/bin/env bash -c 'echo ok'`,
		`echo "x=$(git log -1 --format=%ct)" >>"$GITHUB_ENV"`,
		`docker save -o "$RUNNER_TEMP/image.tar" x 2>&1`,
		`if [ -n "${GITHUB_ENV:-}" ]; then DOCKER_CONFIG="${RUNNER_TEMP:?}/x"; fi`,
	} {
		if _, problems := referencedTexts(root, text, "", true); len(problems) > 0 {
			t.Errorf("referencedTexts(%q): problems %q, want none", text, problems)
		}
	}
}

// TestShellCommands: quotes, substitutions and comments.
func TestShellCommands(t *testing.T) {
	got := shellCommands("a \"b c\" 'd e' $(f g)/h # i\nj ${K:-x}/l `m n`; o")
	want := [][]string{{"f", "g"}, {"a", "b c", "d e", "$(f g)/h"}, {"j", "${K:-x}/l", "`m n`"}, {"m", "n"}, {"o"}}
	if len(got) != len(want) {
		t.Fatalf("shellCommands = %q, want %q", got, want)
	}
	for _, w := range want {
		if !slices.ContainsFunc(got, func(g []string) bool { return slices.Equal(g, w) }) {
			t.Errorf("shellCommands = %q, lacks %q", got, w)
		}
	}
}
