package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// What a step runs (#49 point 1). The rules on a job that builds with
// bake (verify placement, GITHUB_ENV writes, tests by the verified ID)
// read the step's own text and every file it runs. A file is found in two
// ways:
//   - any word of a text that names a file under the root is followed,
//     whatever its position (a wide net: a comment that names a script
//     pulls it in too);
//   - the commands of a shell text are read: the script a command runs
//     (`./x`, `sh x`, `bash "$GITHUB_WORKSPACE/x"`, `. x`), the target
//     of `make`, and a local action's steps.
//
// Paths resolve against the root, the step's working-directory, the
// directories the text cd's into, and, for $(dirname "$0"), the script's
// own directory; $GITHUB_WORKSPACE and ${{ github.workspace }} are the
// root. A command that runs a script the check cannot resolve this way
// (a variable, an absolute path outside the system directories, a file
// that is not there, a make target without an explicit rule) is a
// problem: the caller reports it instead of passing the step unread. So
// is reaching the limit of maxReferenced files.

// maxReferenced bounds how many files referencedTexts follows.
const maxReferenced = 200

// rootMark and dirMark stand for the root and for the directory of the
// script a text is from, after the forms below are replaced.
const (
	rootMark = "@ROOT@"
	dirMark  = "@DIR@"
)

var (
	workspacePrefix = regexp.MustCompile(`\$\{\{\s*(?:github\.workspace|env\.GITHUB_WORKSPACE)\s*\}\}|\$\{GITHUB_WORKSPACE\}|\$GITHUB_WORKSPACE\b|\$\(git rev-parse --show-toplevel\)`)
	cwdPrefix       = regexp.MustCompile(`\$\{PWD\}|\$PWD\b|\$\(pwd\)`)
	scriptDirExpr   = `\$\(dirname\s+(?:--\s+)?"?\$\{?(?:0|BASH_SOURCE(?:\[0\])?)\}?"?\s*\)|\$\{(?:0|BASH_SOURCE(?:\[0\])?)%/\*\}`
	scriptDirPrefix = regexp.MustCompile(`\$\(cd\s+(?:--\s+)?"?(?:` + scriptDirExpr + `)"?\s*&&\s*pwd(?:\s+-P)?\s*\)|` + scriptDirExpr)
	actionPath      = regexp.MustCompile(`\$\{\{\s*github\.action_path\s*\}\}|\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH\b`)
	markNames       = strings.NewReplacer(rootMark, "$GITHUB_WORKSPACE", dirMark, `$(dirname "$0")`)
)

// substitutePrefixes replaces the directory forms the resolver knows by
// rootMark, dirMark or ".".
func substitutePrefixes(text string) string {
	text = scriptDirPrefix.ReplaceAllString(text, dirMark)
	text = workspacePrefix.ReplaceAllString(text, rootMark)
	return cwdPrefix.ReplaceAllString(text, ".")
}

// refText is a file a command names, relative to the root, and its text.
// exec is set for a text that runs: a step's own text, a script a command
// runs, a make target's recipe or a local action's step. The other texts
// are files a word merely names.
type refText struct {
	path, text string
	exec       bool
}

// refItem is a text waiting to be resolved.
type refItem struct {
	text  string
	dirs  []string // absolute directories relative paths resolve against
	file  string   // absolute path of the file the text is from; "" for a step's text
	shell bool     // a shell text: its commands are read
	depth int
}

type refWalk struct {
	root     string
	out      []refText
	problems []string
	src      map[string]string // followed file → its text
	scanned  map[string]bool   // file → its commands were read
	ran      map[string]bool   // file → a command runs it
	binary   map[string]bool   // file → not text
	queue    []refItem
}

// referencedTexts returns what a text runs or names under root (see the
// comment at the top), and the problems: what the check cannot resolve.
// workdir is the step's working-directory ("" for none); shell is false
// for a text that is not shell (actions/github-script).
func referencedTexts(root, text, workdir string, shell bool) ([]refText, []string) {
	w := &refWalk{root: root, src: map[string]string{}, scanned: map[string]bool{}, ran: map[string]bool{}, binary: map[string]bool{}}
	dirs := []string{root}
	if workdir != "" {
		if d, ok := w.dir(workdir, dirs, ""); ok {
			dirs = append(dirs, d)
		} else {
			w.problem("its working-directory %q is not a directory the check can resolve", workdir)
		}
	}
	w.queue = append(w.queue, refItem{text: text, dirs: dirs, shell: shell})
	w.run()
	return w.out, w.problems
}

// referencedFiles returns the files under root that words of a command
// text name (`sh scripts/build`, `./scripts/x`, `bash x.txt`): a script
// runs whatever its name or extension.
func referencedFiles(root, text string) []string {
	w := &refWalk{root: root}
	var files []string
	for _, word := range shellSplit.Split(shellQuoting.Replace(substitutePrefixes(text)), -1) {
		files = append(files, w.existing(word, []string{root}, "")...)
	}
	return files
}

func (w *refWalk) problem(format string, a ...any) {
	p := markNames.Replace(fmt.Sprintf(format, a...))
	if !slices.Contains(w.problems, p) {
		w.problems = append(w.problems, p)
	}
}

func (w *refWalk) run() {
	for len(w.queue) > 0 {
		it := w.queue[0]
		w.queue = w.queue[1:]
		text := substitutePrefixes(it.text)
		dirs := it.dirs
		if it.shell {
			dirs = append(slices.Clone(dirs), w.cdDirs(text, it)...)
		}
		for _, word := range shellSplit.Split(shellQuoting.Replace(text), -1) {
			for _, p := range w.existing(word, dirs, it.file) {
				w.follow(p, false, false, dirs, it.depth)
			}
		}
		if it.shell {
			w.commands(text, dirs, it.file, it.depth, nil)
		}
	}
}

// candidates returns the paths a word can name; ok is false for a word
// the check cannot resolve (a variable, an absolute path, a glob).
func (w *refWalk) candidates(word string, dirs []string, file string) ([]string, bool) {
	word = strings.TrimPrefix(word, "./")
	switch {
	case word == "":
		return nil, false
	case strings.HasPrefix(word, rootMark):
		return []string{filepath.Join(w.root, filepath.FromSlash(strings.TrimPrefix(word, rootMark)))}, true
	case strings.HasPrefix(word, dirMark):
		if file == "" {
			return nil, false
		}
		return []string{filepath.Join(filepath.Dir(file), filepath.FromSlash(strings.TrimPrefix(word, dirMark)))}, true
	case strings.ContainsAny(word, "$`*?") || strings.Contains(word, rootMark) || strings.Contains(word, dirMark) || filepath.IsAbs(word):
		return nil, false
	}
	var out []string
	for _, d := range dirs {
		out = append(out, filepath.Join(d, filepath.FromSlash(word)))
	}
	return out, true
}

// inRoot reports whether p is under the root (not the root itself).
func (w *refWalk) inRoot(p string) bool {
	rel, err := filepath.Rel(w.root, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// targets returns what a path stands for: a regular file, or a
// directory's action.yml/action.yaml.
func targets(p string) ([]string, bool) {
	st, err := os.Stat(p) //nolint:gosec // p is under the root (inRoot)
	switch {
	case err != nil:
		return nil, false
	case st.Mode().IsRegular():
		return []string{p}, true
	case st.IsDir():
		var out []string
		for _, n := range []string{"action.yml", "action.yaml"} {
			if st, err := os.Stat(filepath.Join(p, n)); err == nil && st.Mode().IsRegular() { //nolint:gosec // under the root
				out = append(out, filepath.Join(p, n))
			}
		}
		return out, true
	}
	return nil, false
}

// existing returns the files a word names, if any (words that name
// nothing are arguments, not files). A relative word names a file in
// every directory it may run in (the root, a working-directory, a cd
// target), and all of them are returned: the check cannot tell which
// one the shell reaches (#50 review B, finding 2).
func (w *refWalk) existing(word string, dirs []string, file string) []string {
	if strings.HasPrefix(word, "-") || strings.Contains(word, "=") {
		return nil
	}
	cands, _ := w.candidates(word, dirs, file)
	var out []string
	for _, c := range cands {
		if !w.inRoot(c) {
			continue
		}
		if t, ok := targets(c); ok {
			out = append(out, t...)
		}
	}
	return out
}

// dir resolves a directory word (a working-directory, a cd target).
func (w *refWalk) dir(word string, dirs []string, file string) (string, bool) {
	word = strings.TrimSuffix(substitutePrefixes(word), "/")
	if word == rootMark || word == "." {
		return w.root, true
	}
	cands, ok := w.candidates(word, dirs, file)
	if !ok {
		return "", false
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.IsDir() && (c == w.root || w.inRoot(c)) { //nolint:gosec // under the root
			return c, true
		}
	}
	return "", false
}

// cdDirs are the directories a shell text changes into.
func (w *refWalk) cdDirs(text string, it refItem) []string {
	var out []string
	for _, words := range shellCommands(text) {
		if len(words) < 2 || (words[0] != "cd" && words[0] != "pushd") {
			continue
		}
		for _, a := range words[1:] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if d, ok := w.dir(a, it.dirs, it.file); ok {
				out = append(out, d)
			}
			break
		}
	}
	return out
}

func isActionFile(p string) bool {
	b := filepath.Base(p)
	return b == "action.yml" || b == "action.yaml"
}

// follow adds a file: its text, and the item that resolves what it runs
// or names. script is set when a command runs it, and shell when its
// commands are read as shell. A file that is not text (a binary) is not
// read; running one is a problem (#50 review A, finding 2e).
func (w *refWalk) follow(p string, script, shell bool, dirs []string, depth int) {
	p = filepath.Clean(p)
	rel := filepath.ToSlash(mustRel(w.root, p))
	if _, seen := w.src[p]; !seen {
		if len(w.src) >= maxReferenced {
			w.problem("it names more than %d files; the check stops following them there", maxReferenced)
			return
		}
		src, err := os.ReadFile(p) //nolint:gosec // p is under the root
		if err != nil {
			w.src[p] = ""
			w.out = append(w.out, refText{rel, err.Error(), false})
			return
		}
		if bytes.IndexByte(src[:min(len(src), 8000)], 0) >= 0 {
			w.src[p] = ""
			w.binary[p] = true
			if script {
				w.problem("it runs %s, a binary the check cannot read", rel)
			}
			return
		}
		w.src[p] = string(src)
		if isActionFile(p) {
			w.action(p, src, depth)
			return
		}
		w.out = append(w.out, refText{rel, string(src), script})
		w.scanned[p] = script && shell
		w.queue = append(w.queue, refItem{text: string(src), dirs: dirs, file: p, shell: script && shell, depth: depth})
		if script {
			w.ran[p] = true
		}
		return
	}
	if script && w.binary[p] {
		w.problem("it runs %s, a binary the check cannot read", rel)
		return
	}
	if script && !w.ran[p] {
		w.ran[p] = true
		for i := range w.out {
			if w.out[i].path == rel {
				w.out[i].exec = true
			}
		}
	}
	if script && shell && !w.scanned[p] && !isActionFile(p) {
		w.scanned[p] = true
		w.queue = append(w.queue, refItem{text: w.src[p], dirs: dirs, file: p, shell: true, depth: depth})
	}
}

// action follows a local action: each step's run text and github-script,
// the local actions its steps use, and a JavaScript action's files.
func (w *refWalk) action(p string, src []byte, depth int) {
	rel := filepath.ToSlash(mustRel(w.root, p))
	var a struct {
		Runs struct {
			Using string           `yaml:"using"`
			Main  string           `yaml:"main"`
			Pre   string           `yaml:"pre"`
			Post  string           `yaml:"post"`
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	docs, err := parseYAML(src)
	if err == nil && len(docs) == 1 {
		err = docs[0].Decode(&a)
	}
	if err != nil || len(docs) != 1 {
		w.out = append(w.out, refText{rel, string(src), false})
		w.problem("%s does not parse as one action", rel)
		return
	}
	dirs := []string{w.root}
	for _, f := range []string{a.Runs.Main, a.Runs.Pre, a.Runs.Post} {
		if f != "" {
			w.follow(filepath.Join(filepath.Dir(p), filepath.FromSlash(f)), false, false, dirs, depth)
		}
	}
	for _, step := range a.Runs.Steps {
		stepDirs := dirs
		if wd, _ := step["working-directory"].(string); wd != "" {
			if d, ok := w.dir(wd, dirs, ""); ok {
				stepDirs = append(slices.Clone(dirs), d)
			} else {
				w.problem("%s: working-directory %q is not a directory the check can resolve", rel, wd)
			}
		}
		// $GITHUB_ACTION_PATH and ${{ github.action_path }} are the
		// action's own directory: dirMark, with p as the file.
		if run, ok := step["run"].(string); ok {
			run = actionPath.ReplaceAllString(run, dirMark)
			w.out = append(w.out, refText{rel, run, true})
			w.queue = append(w.queue, refItem{text: run, dirs: stepDirs, file: p, shell: true, depth: depth})
		}
		if script := githubScript(step); script != "" {
			script = actionPath.ReplaceAllString(script, dirMark)
			w.out = append(w.out, refText{rel, script, true})
			w.queue = append(w.queue, refItem{text: script, dirs: stepDirs, file: p, depth: depth})
		}
		if uses, _ := step["uses"].(string); strings.HasPrefix(uses, "./") {
			w.localAction(uses, depth)
		}
	}
}

// localAction follows `uses: ./…`: the action.yml in that directory.
func (w *refWalk) localAction(uses string, depth int) {
	d := filepath.Join(w.root, filepath.FromSlash(strings.TrimSuffix(strings.TrimPrefix(uses, "./"), "/")))
	if t, _ := targets(d); w.inRoot(d) && len(t) > 0 {
		for _, p := range t {
			w.follow(p, false, false, []string{w.root}, depth)
		}
		return
	}
	w.problem("it uses %s, which has no action.yml the check can read", uses)
}

// githubScript returns the script of an actions/github-script step.
func githubScript(step map[string]any) string {
	uses, _ := step["uses"].(string)
	if !strings.HasPrefix(strings.ToLower(uses), "actions/github-script@") {
		return ""
	}
	with, _ := step["with"].(map[string]any)
	s, _ := with["script"].(string)
	return s
}

// shell interpreters: the flag that takes an inline command (the next
// word), and the flags that take a value.
type interpreter struct {
	inline     map[string]bool
	inlineDash bool // -ec, -xc …: a combined flag with c
	values     map[string]bool
	shell      bool // the inline command is shell
}

var (
	shellInterp  = interpreter{inline: map[string]bool{"-c": true}, inlineDash: true, values: map[string]bool{"-o": true, "-O": true, "+o": true}, shell: true}
	interpreters = map[string]interpreter{
		"sh": shellInterp, "bash": shellInterp, "dash": shellInterp, "zsh": shellInterp, "ksh": shellInterp, "ash": shellInterp, "mksh": shellInterp,
		"python": {inline: map[string]bool{"-c": true, "-m": true}, values: map[string]bool{"-W": true, "-X": true}},
		"node":   {inline: map[string]bool{"-e": true, "--eval": true, "-p": true, "--print": true}, values: map[string]bool{"-r": true, "--require": true, "--import": true}},
		"perl":   {inline: map[string]bool{"-e": true, "-E": true}},
		"ruby":   {inline: map[string]bool{"-e": true}},
		"php":    {inline: map[string]bool{"-r": true}},
		"pwsh":   {inline: map[string]bool{"-c": true, "-Command": true}},
		"source": {},
		".":      {},
	}
	interpAlias = map[string]string{"python3": "python", "python2": "python", "nodejs": "node", "pwsh-preview": "pwsh"}
	shellAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)
	// prefixWords run the command after them (and their own options).
	prefixWords = map[string]bool{
		"if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true, "!": true,
		"exec": true, "time": true, "nohup": true, "command": true, "builtin": true, "sudo": true, "env": true, "nice": true, "timeout": true,
	}
	prefixValues = map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true, "-n": true, "-s": true, "-k": true, "--signal": true, "--kill-after": true, "--user": true, "--group": true, "--chdir": true}
	scriptExts   = []string{".sh", ".bash", ".py", ".pl", ".rb", ".js", ".mjs", ".cjs", ".ts", ".php", ".ps1"}
	redirect     = regexp.MustCompile(`^[0-9]*(?:>>?|<<?<?|>&|<&|>\|)`)
	systemDirs   = []string{"/usr/", "/bin/", "/sbin/"}
)

// dropRedirects removes redirections and their targets from a command.
func dropRedirects(words []string) []string {
	var out []string
	for i := 0; i < len(words); i++ {
		if m := redirect.FindString(words[i]); m != "" {
			if m == words[i] {
				i++
			}
			continue
		}
		out = append(out, words[i])
	}
	return out
}

// commandTarget returns what a command runs: the script file it names
// (script), an inline command (inline, shell or not), or make's
// arguments (isMake).
func commandTarget(words []string) (script string, lang int, inline string, inlineShell bool, makeArgs []string, isMake bool) {
	words = dropRedirects(words)
	i := commandStart(words)
	if i >= len(words) {
		return "", 0, "", false, nil, false
	}
	w0, base := words[i], path.Base(words[i])
	switch base {
	case "eval":
		return "", 0, strings.Join(words[i+1:], " "), true, nil, false
	case "make", "gmake":
		return "", 0, "", false, words[i+1:], true
	}
	name := base
	if a, ok := interpAlias[name]; ok {
		name = a
	}
	if in, ok := interpreters[name]; ok {
		lang := langOther
		if in.shell || name == "source" || name == "." {
			lang = langShell
		}
		for j := i + 1; j < len(words); j++ {
			a := words[j]
			switch {
			case a == "-":
				return "", 0, "", false, nil, false // the program comes from stdin
			case in.inline[a] || (in.inlineDash && len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.HasSuffix(a, "c")):
				if j+1 < len(words) {
					return "", 0, words[j+1], in.shell, nil, false
				}
				return "", 0, "", false, nil, false
			case in.values[a] || (in.shell && len(a) > 2 && (a[0] == '-' || a[0] == '+') && a[1] != '-' && strings.ContainsAny(a[len(a)-1:], "oO")):
				j++ // -o pipefail, -euo pipefail: the flag takes the next word
			case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
			default:
				return a, lang, "", false, nil, false
			}
		}
		return "", 0, "", false, nil, false
	}
	if looksLikeScript(w0) || strings.ContainsAny(w0, "$`") {
		return w0, langDirect, "", false, nil, false
	}
	return "", 0, "", false, nil, false
}

// literalCommands returns the variables a shell text assigns only literal
// command names (no $, `, / or space), such as sudo=sudo: running "$sudo"
// runs a command on PATH, not a script.
//
// It returns each such variable with the values it is assigned ("" for
// sudo=). commands substitutes them into the command word and reads the
// command again, so `$SUDO sh x` still runs x (#50 delta review B,
// finding 1).
func literalCommands(text string) map[string][]string {
	out := map[string][]string{}
	bad := map[string]bool{}
	for _, words := range shellCommands(text) {
		for _, wd := range words {
			m := shellAssignValue.FindStringSubmatch(wd)
			if m == nil {
				break
			}
			if strings.ContainsAny(m[2], "$`/ \t") {
				bad[m[1]] = true
			} else if !slices.Contains(out[m[1]], m[2]) {
				out[m[1]] = append(out[m[1]], m[2])
			}
		}
	}
	for n := range bad {
		delete(out, n)
	}
	return out
}

// shellFunction finds the start of a shell function definition, up to
// its opening brace: `name() {` or `function name {`. The name is
// submatch 1 or 2.
var shellFunction = regexp.MustCompile(`(?m)(?:^|[;&|]|\s)(?:function\s+([A-Za-z_][\w:-]*)\s*(?:\(\s*\))?|([A-Za-z_][\w:-]*)\s*\(\s*\))\s*\{`)

// shellFunc is a function a shell text defines: its name and its body,
// without the bodies of the functions defined inside it.
type shellFunc struct {
	name, body string
}

// splitFunctions returns a shell text without its function bodies, and
// the functions. A function defined inside a body is a function of its
// own (the shell defines it by name when the outer one runs), and its
// body is left out of the outer one's.
func splitFunctions(text string) (string, []shellFunc) {
	var top strings.Builder
	var funcs []shellFunc
	rest := text
	for {
		loc := shellFunction.FindStringSubmatchIndex(rest)
		if loc == nil {
			top.WriteString(rest)
			return top.String(), funcs
		}
		n := 2 // function name {
		if loc[n] < 0 {
			n = 4 // name() {
		}
		name := rest[loc[n]:loc[n+1]]
		open := loc[1] - 1
		end := matchClose(rest, open)
		top.WriteString(rest[:open] + "\n")
		body, inner := splitFunctions(rest[open+1 : end])
		funcs = append(funcs, shellFunc{name, body})
		funcs = append(funcs, inner...)
		rest = rest[end+1:]
	}
}

var (
	shellAssignValue = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	bareVar          = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)
	positional       = regexp.MustCompile(`^\$\{?([0-9]+|[@*])\}?$`)
)

// commandStart returns the index of the word a command runs, after
// assignments and the words that run the rest (sudo, env, exec, if …)
// with their options.
func commandStart(words []string) int {
	i := 0
	for i < len(words) {
		base := path.Base(words[i])
		switch {
		case shellAssign.MatchString(words[i]):
			i++
		case prefixWords[base]:
			i++
			for i < len(words) && (strings.HasPrefix(words[i], "-") || (base == "env" && shellAssign.MatchString(words[i]))) {
				if prefixValues[words[i]] {
					i++
				}
				i++
			}
			if base == "timeout" && i < len(words) {
				i++ // the duration
			}
		default:
			return i
		}
	}
	return i
}

// looksLikeScript reports whether a command word names a file rather
// than a command on PATH.
func looksLikeScript(w string) bool {
	if strings.Contains(w, "/") || strings.HasPrefix(w, rootMark) || strings.HasPrefix(w, dirMark) {
		return true
	}
	for _, e := range scriptExts {
		if strings.HasSuffix(w, e) {
			return true
		}
	}
	return false
}

// forwardedArg is an argument that passes on the caller's positional
// parameters: "$@", "$*", "${@}", "$N", "${N}", also with any operator
// after the parameter ("${@:2}", "${1:-x}", the portable ${1+"$@"},
// "${1?msg}"; #68 review B, B1).
var forwardedArg = regexp.MustCompile(`^\$(?:[0-9]+|[@*]|\{(?:[0-9]+|[@*])[^}]*\})$`)

// Copies of the arguments inside a function body (#68 review A, A1;
// review B, B2): an array expansion ("${args[@]}", "${a[*]}", also with
// an operator), and a variable assigned from a value with $@, $*, ${@ or
// ${* (also after local/declare, with +=) or read from a here-string
// with them (read -r -a a <<< "$*").
var (
	arrayArg     = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\][^}]*\}$`)
	assignAnyArg = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)$`)
	allArgs      = regexp.MustCompile(`\$(?:[@*]|\{[@*])`)
	shellName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	readCommands = map[string]bool{"read": true, "mapfile": true, "readarray": true}
)

// argCopies returns the variables the commands of function bodies assign
// from all the arguments (see arrayArg): any word name=value or
// name+=value whose value has $@, $*, ${@ or ${*, and every name after
// read, mapfile or readarray fed by a here-string with them. A plain
// data variable (c=$1, x=date) is not a copy.
func argCopies(cmds [][][]string) map[string]bool {
	out := map[string]bool{}
	for _, body := range cmds {
		for _, words := range body {
			for _, wd := range words {
				if m := assignAnyArg.FindStringSubmatch(wd); m != nil && allArgs.MatchString(m[2]) {
					out[m[1]] = true
				}
			}
			if !hereStringArgs(words) {
				continue
			}
			plain := dropRedirects(words)
			i := commandStart(plain)
			if i >= len(plain) || !readCommands[plain[i]] {
				continue
			}
			for _, a := range plain[i+1:] {
				if shellName.MatchString(a) {
					out[a] = true
				}
			}
		}
	}
	return out
}

// hereStringArgs reports whether a command reads a here-string with all
// the arguments (<<< "$*", <<<"$@").
func hereStringArgs(words []string) bool {
	for k, wd := range words {
		fd, rest, ok := strings.Cut(wd, "<<<")
		if !ok || strings.Trim(fd, "0123456789") != "" {
			continue
		}
		if rest == "" && k+1 < len(words) {
			rest = words[k+1]
		}
		if allArgs.MatchString(rest) {
			return true
		}
	}
	return false
}

// copyCall returns the first argument of a call of a forwarding function
// that is a copy of the arguments (an array expansion, or a variable
// argCopies holds); call starts at the command word.
func copyCall(call []string, fwd, copies map[string]bool) (string, bool) {
	if !fwd[call[0]] {
		return "", false
	}
	for _, a := range call[1:] {
		if arrayArg.MatchString(a) {
			return a, true
		}
		if m := bareVar.FindStringSubmatch(a); m != nil && copies[m[1]] {
			return a, true
		}
	}
	return "", false
}

// shellScope is what command reads a command of a shell text with: the
// variables the text assigns only literal command names
// (literalCommands), and its forwarding functions.
type shellScope struct {
	lit map[string][]string
	fwd map[string]bool
}

// forwardingFunctions returns the names of the functions that run their
// positional parameters as a command (#67): a body with "$@", "$*" or
// "$N" as a command word (also inside a loop, after shift, after a
// prefix such as exec), or a body that passes them on to such a function
// (also a function defined inside another, or through more functions),
// directly or as a copy (copyCall: local a=("$@"); retry "${a[@]}").
// outer holds the forwarding functions of the text an inline command
// (eval, sh -c) is from. The order of definition and call is not read:
// a call before the definition counts as well (an over-report).
func forwardingFunctions(funcs []shellFunc, lit map[string][]string, outer map[string]bool) map[string]bool {
	fwd := map[string]bool{}
	for n := range outer {
		fwd[n] = true
	}
	cmds := make([][][]string, len(funcs))
	for k, f := range funcs {
		cmds[k] = shellCommands(f.body)
	}
	copies := argCopies(cmds)
	for changed := true; changed; {
		changed = false
		for k, f := range funcs {
			if fwd[f.name] {
				continue
			}
			for _, words := range cmds[k] {
				if runsPositional(dropRedirects(words), lit, fwd, copies, 0) {
					fwd[f.name] = true
					changed = true
					break
				}
			}
		}
	}
	return fwd
}

// runsPositional reports whether a command of a function body runs the
// function's positional parameters as a command: as its command word, or
// passed on to a forwarding function, also as a copy (copyCall). A plain
// data variable passed on ("$c", "$x") does not count: it would make
// data such as image-test.sh's "$c" a command (#68 review A). A command
// word in a variable the text assigns only literal command names is
// replaced as in command.
func runsPositional(words []string, lit map[string][]string, fwd, copies map[string]bool, depth int) bool {
	i := commandStart(words)
	if i >= len(words) || depth > 8 {
		return false
	}
	if m := bareVar.FindStringSubmatch(words[i]); m != nil && len(lit[m[1]]) > 0 {
		for _, v := range lit[m[1]] {
			if runsPositional(replaceWord(words, i, strings.Fields(v)), lit, fwd, copies, depth+1) {
				return true
			}
		}
		return false
	}
	if positional.MatchString(words[i]) {
		return true
	}
	if _, ok := forwardedCall(words[i:], fwd); ok {
		return true
	}
	_, ok := copyCall(words[i:], fwd, copies)
	return ok
}

// forwardedCall returns the first argument that passes on positional
// parameters (forwardedArg) in a call of a forwarding function; call
// starts at the command word.
func forwardedCall(call []string, fwd map[string]bool) (string, bool) {
	if !fwd[call[0]] {
		return "", false
	}
	for _, a := range call[1:] {
		if forwardedArg.MatchString(a) {
			return a, true
		}
	}
	return "", false
}

// variableCall returns the first argument with a variable or a command
// substitution ($ or `) in a call of a forwarding function; call starts
// at the command word. At the top level such an argument is reported:
// the function runs it as a command, and the check cannot read what it
// holds ("${args[@]}" after args=("$@"), $cmd after cmd="$*"; #68
// review B, B1). Only forwardedArg makes a function forwarding
// (runsPositional), so a body that passes "$x" on stays as it is.
func variableCall(call []string, fwd map[string]bool) (string, bool) {
	if !fwd[call[0]] {
		return "", false
	}
	for _, a := range call[1:] {
		if strings.ContainsAny(a, "$`") {
			return a, true
		}
	}
	return "", false
}

// replaceWord returns words with the word at i replaced by with.
func replaceWord(words []string, i int, with []string) []string {
	out := append(slices.Clone(words[:i]), with...)
	return append(out, words[i+1:]...)
}

// commands reads the commands of a shell text: the scripts they run,
// inline commands, and make.
//
// Function bodies are read apart from the top level: see command for
// "$@". outer holds the forwarding functions of the text an inline
// command is from (nil for a file or a step).
func (w *refWalk) commands(text string, dirs []string, file string, depth int, outer map[string]bool) {
	if depth > 8 {
		w.problem("its commands nest too deep for the check")
		return
	}
	lit := literalCommands(text)
	top, funcs := splitFunctions(text)
	sc := shellScope{lit: lit, fwd: forwardingFunctions(funcs, lit, outer)}
	for _, words := range shellCommands(top) {
		w.command(words, sc, false, dirs, file, depth)
	}
	for _, f := range funcs {
		for _, words := range shellCommands(f.body) {
			w.command(words, sc, true, dirs, file, depth)
		}
	}
}

// command reads one command. An exception may skip a word, never the
// whole command (#50 delta review B):
//   - a command word that is a variable the text assigns only literal
//     command names ($SUDO with SUDO=sudo) is replaced by each value and
//     the command is read again: sudo is then a prefix, bash an
//     interpreter;
//   - "$@", "$*" or "$N" as the command word inside a function body
//     runs the function's arguments, words of the same text: that word
//     is skipped and the rest of the command read.
//
// "$@", "$*" or "$N" as the command word at the top level forwards the
// caller's arguments as a command. The check does not model that
// (shift, set --, forwarding through more scripts): it is reported
// (#50 delta review B 2; coordinator, G17). So is a call at the top level
// that passes them, or any other variable, to a forwarding function
// (`main "$@"` with `main() { for i in 1 2 3; do "$@" && return 0; done; }`;
// #67; variableCall), and
// any other command word with a variable ("$SAVE", the "$CMD" of
// sh -c "$CMD"; #50 review B, finding 3).
func (w *refWalk) command(words []string, sc shellScope, inFunc bool, dirs []string, file string, depth int) {
	if depth > 8 {
		w.problem("its commands nest too deep for the check")
		return
	}
	words = dropRedirects(words)
	if i := commandStart(words); i < len(words) {
		if m := bareVar.FindStringSubmatch(words[i]); m != nil && len(sc.lit[m[1]]) > 0 {
			for _, v := range sc.lit[m[1]] {
				w.command(replaceWord(words, i, strings.Fields(v)), sc, inFunc, dirs, file, depth+1)
			}
			return
		}
		if positional.MatchString(words[i]) {
			if inFunc {
				w.command(replaceWord(words, i, nil), sc, inFunc, dirs, file, depth+1)
				return
			}
			w.problem("it forwards its arguments as a command (%s), which the check cannot resolve; call the command directly", words[i])
			return
		}
		if !inFunc {
			if arg, ok := forwardedCall(words[i:], sc.fwd); ok {
				w.problem("it forwards its arguments as a command (%s, through the function %s), which the check cannot resolve; call the command directly", arg, words[i])
				return
			}
			if arg, ok := variableCall(words[i:], sc.fwd); ok {
				w.problem("it passes %s to the function %s, which runs its arguments as a command; the check cannot resolve what it holds; call the command directly", arg, words[i])
				return
			}
		}
	}
	script, lang, inline, inlineShell, makeArgs, isMake := commandTarget(words)
	switch {
	case inline != "" && inlineShell:
		w.commands(inline, dirs, file, depth+1, sc.fwd)
	case isMake:
		w.makeCall(makeArgs, dirs, file, depth)
	case script != "":
		w.script(script, lang, dirs, file, depth)
	}
}

// script follows a script a command runs, or records it as a problem.
// Every existing candidate is followed (see existing). lang says how the
// script is read: as shell, or (langOther) only for image commands;
// langDirect means the command runs the file itself, and its #! line
// decides.
func (w *refWalk) script(word string, lang int, dirs []string, file string, depth int) {
	for _, d := range systemDirs {
		if strings.HasPrefix(word, d) {
			return
		}
	}
	found := false
	if cands, ok := w.candidates(word, dirs, file); ok {
		for _, c := range cands {
			if !w.inRoot(c) {
				continue
			}
			if t, ok := targets(c); ok && len(t) > 0 {
				for _, p := range t {
					w.follow(p, true, scriptIsShell(p, lang), dirs, depth+1)
				}
				found = true
			}
		}
	}
	if !found {
		w.problem("it runs %s, which the check cannot resolve to a file in the repository", word)
	}
}

// The language a script is read in (script, commandTarget).
const (
	langDirect = iota // ./x: its #! line decides
	langShell
	langOther
)

// scriptIsShell reports whether a script is read as shell: run by a
// shell, or run directly with a shell #! line or none (execve falls back
// to /bin/sh). A Python or other script is only scanned for image
// commands; its words are not resolved as commands (#50 review B, note 4).
func scriptIsShell(p string, lang int) bool {
	switch lang {
	case langShell:
		return true
	case langOther:
		return false
	}
	src, err := os.ReadFile(p) //nolint:gosec // p is under the root
	if err != nil || !bytes.HasPrefix(src, []byte("#!")) {
		return true
	}
	first, _, _ := bytes.Cut(src, []byte("\n"))
	f := strings.Fields(strings.TrimPrefix(string(first), "#!"))
	if len(f) == 0 {
		return true
	}
	prog := path.Base(f[0])
	if prog == "env" {
		prog = ""
		for _, a := range f[1:] {
			if !strings.HasPrefix(a, "-") {
				prog = path.Base(a)
				break
			}
		}
	}
	return interpreters[prog].shell
}

// makeCall follows `make [options] [targets]`: the recipes of the named
// targets (or the default goal) and their prerequisites.
func (w *refWalk) makeCall(args []string, dirs []string, file string, depth int) {
	var dir, mf string
	var goals []string
	for j := 0; j < len(args); j++ {
		a := args[j]
		next := func() string {
			if j+1 < len(args) {
				j++
				return args[j]
			}
			return ""
		}
		switch {
		case a == "-C" || a == "--directory":
			dir = next()
		case strings.HasPrefix(a, "--directory="):
			dir = strings.TrimPrefix(a, "--directory=")
		case strings.HasPrefix(a, "-C"):
			dir = a[2:]
		case a == "-f" || a == "--file" || a == "--makefile":
			mf = next()
		case strings.HasPrefix(a, "--file=") || strings.HasPrefix(a, "--makefile="):
			_, mf, _ = strings.Cut(a, "=")
		case strings.HasPrefix(a, "-f") && !strings.HasPrefix(a, "--"):
			mf = a[2:]
		case a == "-I" || a == "-o" || a == "-W" || a == "--include-dir" || a == "--old-file" || a == "--what-if":
			next()
		case (a == "-j" || a == "-l") && j+1 < len(args) && strings.Trim(args[j+1], "0123456789.") == "":
			next()
		case strings.HasPrefix(a, "-") || strings.Contains(a, "="):
		default:
			goals = append(goals, a)
		}
	}
	makeDirs := dirs
	if dir != "" {
		d, ok := w.dir(dir, dirs, file)
		if !ok {
			w.problem("it runs make -C %s, a directory the check cannot resolve", dir)
			return
		}
		makeDirs = []string{d}
	}
	var mfPath string
	if mf != "" {
		cands, _ := w.candidates(mf, makeDirs, file)
		for _, c := range cands {
			if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && w.inRoot(c) { //nolint:gosec // under the root
				mfPath = c
				break
			}
		}
	} else {
	find:
		for _, d := range makeDirs {
			for _, n := range []string{"GNUmakefile", "makefile", "Makefile"} {
				if st, err := os.Stat(filepath.Join(d, n)); err == nil && st.Mode().IsRegular() { //nolint:gosec // under the root
					mfPath = filepath.Join(d, n)
					break find
				}
			}
		}
	}
	if mfPath == "" {
		w.problem("it runs make, but the check finds no Makefile for it")
		return
	}
	for _, g := range goals {
		if strings.ContainsAny(g, "$`") {
			w.problem("it runs make with the target %s, which the check cannot resolve", g)
			return
		}
	}
	// The Makefile and every file it includes are texts of the step as a
	// whole, so the image-use and GITHUB_ENV rules read every recipe line
	// whatever make runs (#50 review B, finding 1; this over-reports).
	makeDir := filepath.Dir(mfPath)
	var files []string
	src := w.readMake(mfPath, makeDir, &files, 0)
	defer func() { // after the recipe's own text
		for _, f := range files {
			w.follow(f, false, false, makeDirs, depth)
		}
	}()
	rel := filepath.ToSlash(mustRel(w.root, mfPath))
	rules, order, vars := parseMakefile([]byte(src))
	if len(goals) == 0 {
		for _, t := range order {
			if !strings.HasPrefix(t, ".") && !strings.ContainsAny(t, "%$") {
				goals = append(goals, t)
				break
			}
		}
	}
	var recipe, missing []string
	seen := map[string]bool{}
	for _, g := range goals {
		if rules[g] == nil {
			w.problem("it runs make %s, which has no explicit rule in %s", g, rel)
			continue
		}
		recipe = append(recipe, makeRecipe(rules, g, seen, &missing)...)
	}
	for _, p := range missing {
		if st, err := os.Stat(filepath.Join(makeDir, filepath.FromSlash(p))); err != nil || !st.Mode().IsRegular() { //nolint:gosec // a prerequisite name, read only for Stat
			w.problem("it runs make, and the prerequisite %s has neither a rule in %s nor a file the check can read", p, rel)
		}
	}
	if len(recipe) == 0 {
		return
	}
	text := expandMake(strings.Join(recipe, "\n"), vars)
	rt := refText{rel + " (make " + strings.Join(goals, " ") + ")", text, true}
	if slices.Contains(w.out, rt) {
		return // the same make call twice (`"$@" || "$@"`)
	}
	w.out = append(w.out, rt)
	w.queue = append(w.queue, refItem{text: text, dirs: makeDirs, file: mfPath, shell: true, depth: depth + 1})
}

type makeRule struct {
	prereqs, recipe []string
}

var (
	makeIncludeLine = regexp.MustCompile(`^\s*(-|s)?include\s+(.*)$`)
	makeDirective   = regexp.MustCompile(`^\s*(ifeq|ifneq|ifdef|ifndef|define|undefine|vpath)\b|^\s*(?:override\s+|export\s+)?(\.DEFAULT_GOAL|\.RECIPEPREFIX|\.ONESHELL|\.SECONDEXPANSION)\b|\$[({](eval|call|value)\s`)
)

// makeUnmodelled returns the first construct of a Makefile text that
// parseMakefile does not model (conditionals, define, .DEFAULT_GOAL,
// $(eval)/$(call) …), or "". A make call on such a Makefile is reported
// rather than read partly.
func makeUnmodelled(src string) string {
	for _, l := range makeLogicalLines([]byte(src)) {
		if m := makeDirective.FindStringSubmatch(l.text); m != nil {
			c := m[1] + m[2] + m[3]
			if m[3] != "" {
				c = "$(" + m[3] + ")"
			}
			return fmt.Sprintf("%s (line %d)", c, l.line)
		}
	}
	return ""
}

// readMake returns a Makefile's text with its literal includes inlined
// (relative to make's directory), and adds every file it read to files.
// An include the check cannot resolve is a problem: a path outside the
// root, or one that literalInclude does not allow (#92), such as a `$`,
// `~`, `#`, quote, backslash or glob character, which make expands or
// strips.
func (w *refWalk) readMake(p, makeDir string, files *[]string, depth int) string {
	p = filepath.Clean(p)
	if slices.Contains(*files, p) || depth > 5 {
		return ""
	}
	src, err := os.ReadFile(p) //nolint:gosec // under the root
	if err != nil {
		w.problem("it runs make, but %s does not read: %v", mustRel(w.root, p), err)
		return ""
	}
	*files = append(*files, p)
	if c := makeUnmodelled(string(src)); c != "" {
		w.problem("it runs make, but %s uses %s, which the check does not model", filepath.ToSlash(mustRel(w.root, p)), c)
	}
	var b strings.Builder
	for _, l := range strings.Split(string(src), "\n") {
		m := makeIncludeLine.FindStringSubmatch(l)
		if m == nil || strings.HasPrefix(l, "\t") {
			b.WriteString(l + "\n")
			continue
		}
		for _, f := range strings.Fields(m[2]) {
			inc := filepath.Join(makeDir, filepath.FromSlash(f))
			st, err := os.Stat(inc) //nolint:gosec // checked below to be under the root
			switch {
			case !literalInclude(f) || !w.inRoot(inc):
				w.problem("it runs make, but %s includes %s, which the check cannot resolve", mustRel(w.root, p), f)
			case err == nil && st.Mode().IsRegular():
				b.WriteString(w.readMake(inc, makeDir, files, depth+1))
			case m[1] == "":
				w.problem("it runs make, but %s includes %s, which is not there", mustRel(w.root, p), f)
			}
		}
	}
	return b.String()
}

var (
	makeAssign   = regexp.MustCompile(`^(?:(?:export|override|private)\s+)*([A-Za-z_.][A-Za-z0-9_.-]*)\s*(:{1,3}=|[?+!]?=)\s*(.*)$`)
	makeRuleLine = regexp.MustCompile(`^([^\s:=#][^:=#]*?)\s*::?(?:[^=]|$)(.*)$`)
	makeVarRef   = regexp.MustCompile(`\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]`)
)

// parseMakefile returns a Makefile's explicit rules, their order and the
// variables it assigns (the last assignment wins; += appends).
func parseMakefile(src []byte) (map[string]*makeRule, []string, map[string]string) {
	rules := map[string]*makeRule{}
	var order []string
	vars := map[string]string{}
	var current []*makeRule
	for _, l := range makeLogicalLines(src) {
		t := l.text
		if strings.HasPrefix(t, "\t") {
			for _, r := range current {
				r.recipe = append(r.recipe, strings.TrimPrefix(t, "\t"))
			}
			continue
		}
		trimmed := strings.TrimSpace(t)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		current = nil
		if m := makeAssign.FindStringSubmatch(trimmed); m != nil {
			v := strings.TrimSpace(m[3])
			if m[2] == "+=" && vars[m[1]] != "" {
				v = vars[m[1]] + " " + v
			}
			if m[2] != "?=" || vars[m[1]] == "" {
				vars[m[1]] = v
			}
			continue
		}
		m := makeRuleLine.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		_, rest, _ := strings.Cut(trimmed, ":")
		rest = strings.TrimPrefix(rest, ":")
		if strings.Contains(rest, "=") {
			continue // a target-specific variable
		}
		prereqs, inline, hasInline := strings.Cut(rest, ";")
		for _, tg := range strings.Fields(expandMake(m[1], vars)) {
			r := rules[tg]
			if r == nil {
				r = &makeRule{}
				rules[tg] = r
				order = append(order, tg)
			}
			r.prereqs = append(r.prereqs, strings.Fields(expandMake(prereqs, vars))...)
			if hasInline {
				r.recipe = append(r.recipe, inline)
			}
			current = append(current, r)
		}
	}
	return rules, order, vars
}

// makeRecipe returns the recipe lines of a target and of its
// prerequisites, prerequisites first. A prerequisite without a rule is
// added to missing (it must be a file).
func makeRecipe(rules map[string]*makeRule, t string, seen map[string]bool, missing *[]string) []string {
	r := rules[t]
	if r == nil || seen[t] {
		return nil
	}
	seen[t] = true
	var out []string
	for _, p := range r.prereqs {
		if p == "|" {
			continue // order-only prerequisites follow
		}
		if rules[p] == nil {
			if !slices.Contains(*missing, p) {
				*missing = append(*missing, p)
			}
			continue
		}
		out = append(out, makeRecipe(rules, p, seen, missing)...)
	}
	for _, l := range r.recipe {
		out = append(out, strings.TrimLeft(strings.TrimSpace(l), "@-+"))
	}
	return out
}

// expandMake replaces make variable references in recipe text: a
// variable the Makefile assigns by its value, $(MAKE) by make, $(CURDIR)
// by ".", and any other variable by the shell variable of that name
// (make reads it from the environment); $$ becomes $.
func expandMake(s string, vars map[string]string) string {
	const dollar = "\x00"
	s = strings.ReplaceAll(s, "$$", dollar)
	for range 8 {
		next := makeVarRef.ReplaceAllStringFunc(s, func(ref string) string {
			name := makeVarRef.FindStringSubmatch(ref)[1]
			switch name {
			case "MAKE":
				return "make"
			case "CURDIR":
				return "."
			}
			if v, ok := vars[name]; ok {
				return strings.ReplaceAll(v, "$$", dollar)
			}
			return dollar + name
		})
		if next == s {
			break
		}
		s = next
	}
	return strings.ReplaceAll(s, dollar, "$")
}

// shellCommands splits shell text into simple commands of words. Quotes
// are removed but their content stays in one word; $(…), ${…} and `…`
// stay in the word as written, and the commands inside $(…) and `…` are
// returned as commands of their own. Comments are dropped. It is an
// approximation; the rules that use it report what they cannot resolve.
func shellCommands(s string) [][]string {
	var out [][]string
	var cur []string
	var w strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			cur = append(cur, w.String())
			w.Reset()
			inWord = false
		}
	}
	endCmd := func() {
		endWord()
		if len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
	}
	// subst copies $(…), ${…} or `…` starting at i into the word, and
	// returns the index of its last character.
	subst := func(i int) int {
		var end int
		if s[i] == '`' {
			j := strings.IndexByte(s[i+1:], '`')
			end = len(s) - 1
			if j >= 0 {
				end = i + 1 + j
			}
			if end > i+1 {
				out = append(out, shellCommands(s[i+1:end])...)
			}
		} else {
			end = matchClose(s, i+1)
			if s[i+1] == '(' && end > i+2 {
				out = append(out, shellCommands(s[i+2:end])...)
			}
		}
		w.WriteString(s[i : end+1])
		inWord = true
		return end
	}
	isSubst := func(i int) bool {
		return s[i] == '`' || (s[i] == '$' && i+1 < len(s) && (s[i+1] == '(' || s[i+1] == '{'))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 < len(s) {
				if s[i+1] != '\n' {
					w.WriteByte(s[i+1])
					inWord = true
				}
				i++
			}
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1
			}
			w.WriteString(s[i+1 : i+1+j])
			inWord = true
			i += j + 1
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				switch {
				case s[i] == '\\' && i+1 < len(s):
					i++
					w.WriteByte(s[i])
				case isSubst(i):
					i = subst(i)
				default:
					w.WriteByte(s[i])
				}
			}
		case isSubst(i):
			i = subst(i)
		case c == '#' && !inWord:
			for i+1 < len(s) && s[i+1] != '\n' {
				i++
			}
		case c == '(' && inWord && strings.HasSuffix(w.String(), "="):
			// An array assignment, a=(…) or a+=(…): one word.
			end := matchClose(s, i)
			w.WriteString(s[i : end+1])
			i = end
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case strings.IndexByte("\n;&|(){}", c) >= 0:
			endCmd()
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	endCmd()
	return out
}

// matchClose returns the index of the bracket that closes the one at
// open, or the last index.
func matchClose(s string, open int) int {
	o := s[open]
	c := byte(')')
	if o == '{' {
		c = '}'
	}
	depth := 0
	for k := open; k < len(s); k++ {
		switch s[k] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return len(s) - 1
}
