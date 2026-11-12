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

// TestFunctionForwarding (#67): a top-level call that passes positional
// parameters to a function that runs them as a command (directly or
// through more functions) is reported like top-level forwarding; a
// function that takes them as arguments, or a forwarding function called
// with literal words or from inside another function, is not.
func TestFunctionForwarding(t *testing.T) {
	root := t.TempDir()
	fwd := func(arg, fn string) string {
		return "it forwards its arguments as a command (" + arg + ", through the function " + fn + "), which the check cannot resolve; call the command directly"
	}
	pass := func(arg, fn string) string {
		return "it passes " + arg + " to the function " + fn + ", which runs its arguments as a command; the check cannot resolve what it holds; call the command directly"
	}
	for _, c := range []struct{ text, want string }{
		{"main() { for i in 1 2 3; do \"$@\" && return 0; done; return 1; }\nmain \"$@\"", fwd("$@", "main")},
		{"function main { while ! \"$@\"; do sleep 1; done; }\nmain \"$@\"", fwd("$@", "main")},
		{"main()\n{\n\texec \"${@}\"\n}\nmain \"${@}\"", fwd("${@}", "main")},
		{"r() { sudo -E \"$1\"; }\nr \"$1\"", fwd("$1", "r")},
		{"r() { \"$@\"; }\nr --verbose \"${@:2}\"", fwd("${@:2}", "r")},
		{"r() { n=$1; shift; timeout 5 \"$@\"; }\nr \"$*\"", fwd("$*", "r")},
		{"S=sudo\nr() { $S \"$@\"; }\nr \"$@\"", fwd("$@", "r")},
		{"main() { inner() { \"$@\"; }; inner \"$@\"; }\nmain \"$@\"", fwd("$@", "main")},
		{"a() { \"$@\"; }\nb() { a \"$@\"; }\nc() { b \"$1\" x; }\nif c \"$@\"; then :; fi", fwd("$@", "c")},
		{"main() { \"$@\"; }\neval 'main \"$@\"'", fwd("$@", "main")},
		{"main() { \"$@\"; }\nout=$(main \"$@\")", fwd("$@", "main")},
		// #68 review B, B1: any operator, and any variable at the top level.
		{"main() { \"$@\"; }\nmain ${1+\"$@\"}", fwd("${1+\"$@\"}", "main")},
		{"main() { \"$@\"; }\nmain \"${1=x}\"", fwd("${1=x}", "main")},
		{"inner() { \"$@\"; }\nmain() { inner ${1+\"$@\"}; }\nmain \"$@\"", fwd("$@", "main")},
		{"main() { \"$@\"; }\nargs=(\"$@\")\nmain \"${args[@]}\"", pass("${args[@]}", "main")},
		{"main() { \"$@\"; }\ncmd=\"$*\"\nmain $cmd", pass("$cmd", "main")},
		{"main() { \"$@\"; }\nmain \"$(cat cmd.txt)\"", pass("$(cat cmd.txt)", "main")},
		{"main() { \"$@\"; }\nmain \"$HOME\" \"$@\"", fwd("$@", "main")},
		// #68 review A, A1 / review B, B2: a copy of the arguments made in
		// a body and passed on makes that function forwarding.
		{"retry() { \"$@\"; }\nmain() { local args=(\"$@\"); retry \"${args[@]}\"; }\nmain \"$@\"", fwd("$@", "main")},
		{"retry() { \"$@\"; }\nmain() { declare -a a; a+=(\"$@\"); retry \"${a[*]:0}\"; }\nmain \"$@\"", fwd("$@", "main")},
		{"run() { \"$@\"; }\nmain() { local c=\"$*\"; run $c; }\nmain \"$@\"", fwd("$@", "main")},
		{"run() { \"$@\"; }\nmain() { c=\"${@:2}\"; run \"${c}\"; }\nmain \"$@\"", fwd("$@", "main")},
		{"run() { \"$@\"; }\nmain() { local a; read -r -a a <<< \"$*\"; run \"${a[@]}\"; }\nmain \"$@\"", fwd("$@", "main")},
		{"run() { \"$@\"; }\nmain() { read -r line <<<\"$@\"; run $line; }\nmain \"$@\"", fwd("$@", "main")},
		{"run() { \"$@\"; }\nmain() { mapfile -t a <<< \"$*\"; run \"${a[@]}\"; }\nmain \"$@\"", fwd("$@", "main")},
	} {
		_, problems := referencedTexts(root, c.text, "", true)
		if !slices.Contains(problems, c.want) {
			t.Errorf("referencedTexts(%q): problems %q, want %q", c.text, problems, c.want)
		}
	}
	for _, text := range []string{
		"say() { echo \"$1\"; }\nsay \"$@\"",
		"flag() { git log --format \"$1\"; }\nflag \"$1\"",
		"stamp() { date -u; }\nstamp \"$@\"",
		"each() { for a in \"$@\"; do echo \"$a\"; done; }\neach \"$@\"",
		"quietly() { \"$@\" >/dev/null; }\nquietly date -u",
		"run() { \"$@\"; }\nouter() { run \"$@\"; }\nouter make --version",
		"run() { \"$@\"; }\necho run \"$@\"",
		"inner() { \"$@\"; }\nmain() { inner date; }\nmain \"$@\"",
		// A body that passes a variable on does not make its function
		// forwarding; only the top-level call is held to that.
		"inner() { \"$@\"; }\nmain() { x=date; inner \"$x\"; }\nmain \"$@\"",
		"say() { echo \"$1\"; }\nsay \"$HOME\" `date`",
		// Data passed on in a body is not a copy of the arguments: $1
		// copies, values without $@/$*, and arrays to a function that
		// does not forward (image-test.sh's "${health_flags[@]}").
		"inner() { \"$@\"; }\nmain() { local c=$1 want=$2; inner \"$c\" $want; }\nmain \"$@\"",
		"inner() { \"$@\"; }\nmain() { local n=\"$#\"; inner $n; }\nmain \"$@\"",
		"inner() { \"$@\"; }\nmain() { read -r x <<< \"$1\"; inner $x; }\nmain \"$@\"",
		"start() { docker run -d \"$@\"; }\nf=(--rm)\nmain() { start \"${f[@]}\" \"$@\"; }\nmain \"$@\"",
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
