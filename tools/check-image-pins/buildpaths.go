package main

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Other build paths (round 4, defence in depth): images are built only
// through `make images` (local mode) and the allowlisted
// docker/bake-action step (build mode). In workflows, composite actions,
// scripts and Makefiles the check reports every other way to build an
// image. The real guarantee in CI is -verify-built, which compares the
// tested and uploaded images with the checked build's output; this rule
// makes a second build path visible in review instead of only at run
// time.

// shellQuoting are the characters removed before matching, so quoting
// tricks such as ba""ke (or with single quotes) and ba\ke match like bake.
var shellQuoting = strings.NewReplacer(`"`, "", "'", "", `\`, "", "`", "")

// shellSplit splits normalised shell text into words.
var shellSplit = regexp.MustCompile(`[\s;&|()<>{}]+`)

// commandSplit splits normalised text into commands, and wordSplit a
// command into words. Besides the shell's own separators, words also end
// at , [ and ]: a step with `shell: python` (or a script in another
// language) writes a command as a list, ["docker","build","."], which
// reads as docker build . once the quotes are gone (#46, A1).
var (
	commandSplit = regexp.MustCompile(`[;&|(){}\n]+`)
	wordSplit    = regexp.MustCompile(`[\s<>,\[\]]+`)
)

// normalizeShell lower-cases text, drops quoting characters and joins
// backslash-continued lines.
func normalizeShell(text string) string {
	text = strings.ReplaceAll(text, "\\\n", " ")
	return strings.ToLower(shellQuoting.Replace(text))
}

// joinBrackets replaces a newline inside open ( or [ by a space: a list
// or a call split over lines, as black and gofmt write them
// (`subprocess.run(\n    [\n        "docker",\n        "build", …`), reads
// as one command (#49 point 3). An unbalanced bracket joins the rest of
// the text, which only adds matches.
func joinBrackets(text string) string {
	b := []byte(text)
	depth := 0
	for i, c := range b {
		switch c {
		case '(', '[':
			depth++
		case ')', ']':
			depth = max(depth-1, 0)
		case '\n':
			if depth > 0 {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

// commands splits text into commands of words (normalised).
func commands(text string) [][]string {
	var out [][]string
	for _, c := range commandSplit.Split(joinBrackets(normalizeShell(text)), -1) {
		var words []string
		for _, w := range wordSplit.Split(c, -1) {
			if w != "" {
				words = append(words, w)
			}
		}
		if len(words) > 0 {
			out = append(out, words)
		}
	}
	return out
}

// knownVerbs are the subcommands the matchers look for. A word after an
// option that is one of them is read as the subcommand, not as the
// option's value.
var knownVerbs = map[string]bool{
	"build": true, "bake": true, "b": true, "bud": true, "image": true, "builder": true,
	"buildx": true, "compose": true, "up": true, "run": true, "create": true, "watch": true,
	"save": true, "push": true, "tag": true, "imagetools": true,
}

// boolOptions are global options known to take no value, so the word
// after them is the subcommand even when it is not a known verb.
var boolOptions = map[string]bool{
	"-d": true, "--debug": true, "--tls": true, "--tlsverify": true,
	"--dry-run": true, "--compatibility": true, "--all-resources": true,
}

// valueOptions are global options of docker, buildx, Compose and nerdctl
// known to take a value: the word after them is always that value (so
// `docker buildx --builder b build` is a build, not bake's alias b).
var valueOptions = map[string]bool{
	"-c": true, "--context": true, "-h": true, "--host": true, "--config": true,
	"-l": true, "--log-level": true, "--builder": true, "-f": true, "--file": true,
	"-p": true, "--project-name": true, "--profile": true, "--env-file": true,
	"--project-directory": true, "-n": true, "--namespace": true, "-a": true, "--address": true,
}

// subcommand returns the first word of rest that is not an option or an
// option's value, and the words after it. An option in valueOptions takes
// the next word as its value. Any other option without `=` that is not
// known to be boolean may take the next word as its value, unless that
// word is a known verb (#46, A1).
func subcommand(rest []string) (string, []string) {
	value, maybeValue := false, false
	for j, w := range rest {
		switch {
		case value:
			value = false
			continue
		case strings.HasPrefix(w, "-"):
			value = valueOptions[w]
			maybeValue = !value && !strings.Contains(w, "=") && !boolOptions[w]
			continue
		case maybeValue && !knownVerbs[w]:
			maybeValue = false
			continue
		}
		return w, rest[j+1:]
	}
	return "", nil
}

// engines are the container CLIs whose subcommands are matched.
var engines = map[string]bool{"docker": true, "podman": true, "nerdctl": true}

// composeBuild returns the build a Compose command runs: `build`,
// `watch`, any subcommand with --build or --build=<value>, up and create
// without --no-build, and every run: they build each service that has
// `build:` and no image yet (#49 point 2). Compose's run has no
// --no-build (Compose v5.6.1: "unknown flag"), so it is always a build;
// start services with `up -d --no-build` and use `exec` instead (#50
// review A, finding 1).
func composeBuild(rest []string) string {
	sub, after := subcommand(rest)
	switch {
	case sub == "build" || sub == "watch":
		return "compose " + sub
	case sub != "" && slices.ContainsFunc(after, func(w string) bool { return w == "--build" || strings.HasPrefix(w, "--build=") }):
		return "compose " + sub + " --build"
	case sub == "run":
		return "compose run, which builds and has no --no-build (use up -d --no-build and exec)"
	case (sub == "up" || sub == "create") && !slices.Contains(after, "--no-build"):
		return "compose " + sub + " without --no-build"
	}
	return ""
}

// buildCommands returns the image build commands in a text: build,
// image build and builder build of docker, podman and nerdctl; any buildx
// build/bake/b (also as the docker-buildx plugin binary); Compose builds
// (`docker compose build`, `… up --build`, `… up` without --no-build,
// `docker-compose build`, `podman-compose`, `nerdctl compose`); buildctl;
// and buildah build.
// Global options before a subcommand are skipped.
func buildCommands(text string) []string {
	var found []string
	for _, words := range commands(text) {
		for i, w := range words {
			base := w[strings.LastIndex(w, "/")+1:]
			rest := words[i+1:]
			switch {
			case base == "buildx" || base == "docker-buildx":
				if sub, _ := subcommand(rest); sub == "build" || sub == "bake" || sub == "b" {
					found = append(found, "buildx "+sub)
				}
			case engines[base]:
				sub, after := subcommand(rest)
				switch sub {
				case "build":
					found = append(found, base+" build")
				case "image", "builder":
					if sub2, _ := subcommand(after); sub2 == "build" {
						found = append(found, base+" "+sub+" build")
					}
				case "compose":
					if c := composeBuild(after); c != "" {
						found = append(found, base+" "+c)
					}
				}
			case base == "docker-compose" || base == "podman-compose":
				if c := composeBuild(rest); c != "" {
					found = append(found, base+" "+strings.TrimPrefix(c, "compose "))
				}
			case base == "buildctl" || base == "buildctl-daemonless.sh":
				found = append(found, "buildctl")
			case base == "buildah":
				if sub, _ := subcommand(rest); sub == "build" || sub == "bud" {
					found = append(found, "buildah build")
				}
			}
		}
	}
	return found
}

// imageUses returns what a text does with an existing image that the
// verify rule covers (#46, A3): docker (or podman, nerdctl) save, push
// and tag, also as `image save|push|tag`; and the other ways an image
// leaves the runner (#49 point 5): Compose push, `buildx imagetools
// create`, crane and skopeo (also `skopeo copy docker-daemon:`, point 9).
func imageUses(text string) []string {
	var found []string
	for _, words := range commands(text) {
		for i, w := range words {
			base := w[strings.LastIndex(w, "/")+1:]
			rest := words[i+1:]
			switch {
			case engines[base]:
				sub, after := subcommand(rest)
				switch sub {
				case "image":
					sub, _ = subcommand(after)
				case "compose":
					if s, _ := subcommand(after); s == "push" {
						found = append(found, "compose push")
					}
					continue
				}
				if sub == "save" || sub == "push" || sub == "tag" {
					found = append(found, "docker "+sub)
				}
			case base == "docker-compose" || base == "podman-compose":
				if s, _ := subcommand(rest); s == "push" {
					found = append(found, "compose push")
				}
			case base == "buildx" || base == "docker-buildx":
				if s, after := subcommand(rest); s == "imagetools" {
					if s2, _ := subcommand(after); s2 == "create" {
						found = append(found, "buildx imagetools create")
					}
				}
			case base == "crane" || base == "gcrane":
				found = append(found, "crane")
			case base == "skopeo":
				found = append(found, "skopeo")
			}
		}
	}
	return found
}

// otherPushes are the image uses that are reported after the build in
// any form: the image leaves the runner only by `docker push` of a name
// the same step tagged from the verified image ID.
var otherPushes = map[string]bool{"compose push": true, "buildx imagetools create": true, "crane": true, "skopeo": true}

// isBuildAction reports whether a `uses:` names an action that builds
// images: docker/build-push-action, docker/bake-action and any other
// docker/* action except the setup ones, plus actions whose name says
// they build images. bake-action is allowed only in the exact form the
// workflow rule checks.
func isBuildAction(uses string) bool {
	u := strings.ToLower(uses)
	name, _, _ := strings.Cut(u, "@")
	switch name {
	case "docker/setup-buildx-action", "docker/setup-qemu-action", "docker/login-action", "docker/metadata-action":
		return false
	}
	if strings.HasPrefix(name, "docker/") {
		return true
	}
	for _, s := range []string{"build-push", "bake", "buildah", "kaniko", "image-build", "docker-build", "github-builder"} {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

// CheckMakefile is the Makefile side of rule 5 after round 4: a Makefile
// or *.mk file holds no `buildx` and no BUILDX_ at all (make images calls
// `check-image-pins -bake-local`, which runs bake itself), and no other
// image build command.
//
// It also reports a line that sets or exports PATH or HOME, or that
// names DOCKER_CONFIG, DOCKER_HOST or DOCKER_CONTEXT (#46, B N3): local
// mode keeps these from its caller (passEnv) so the docker CLI finds
// itself, its plugins and its daemon, and make passes its own value of
// an environment variable to a recipe even without `export`.
//
// And it reports what reroutes `$(GO) run ./tools/check-image-pins
// -bake-local` itself or hides lines from this rule (#49 point 8): SHELL
// or .SHELLFLAGS set; GOFLAGS, GOENV or GOWORK set or exported (CI fixes
// them in the check steps' prefix); any text that sets GO outside the
// allowlisted lines of checkMakeGo (#51 item 4); an include of anything
// but a relative path of letters, digits, `.`, `_`, `-` and `/` ending
// in .mk, not under ../ and not in a skipped directory (literalInclude,
// #92); and a variable name that is computed (`export PA$(E)TH`).
//
// The include rule reads the line before quote removal, and it is an
// allowlist, not a model of how make reads an include path: quotes,
// `\`, `~`, `#`, `$` and glob characters each change the file make
// includes (`include "x.mk"` reads a file named `"x.mk"`,
// `-include evil.cfg#.mk` reads `evil.cfg`), and after three review
// rounds with new forms (#91, #92) every character outside the set is
// reported. A file whose name does not end in .mk is not classified as a
// Makefile by the walk, so this function's rules would never run on it
// (readMake still reads its text when a job runs make).
//
// These rules are a fast filter that fails closed on the forms they
// know, not a proof that a Makefile is safe (see checkMakeGo and
// TestMakefileKnownLimits for what they do not catch).
func CheckMakefile(src []byte) []Finding {
	out := checkMakeGo(src)
	for _, l := range makeLogicalLines(src) {
		n := normalizeShell(l.text)
		if strings.Contains(n, "buildx") {
			out = append(out, Finding{l.line, "a Makefile may not mention buildx or BUILDX_ variables: images are built only through `check-image-pins -bake-local`"})
			continue
		}
		raw := shellQuoting.Replace(l.text)
		if m := makeDockerEnv.FindString(raw); m != "" {
			out = append(out, Finding{l.line, "a Makefile may not name " + m + ": `check-image-pins -bake-local` passes it to docker"})
			continue
		}
		if m := makeSetEnv.FindStringSubmatch(raw); m != nil {
			out = append(out, Finding{l.line, "a Makefile may not set or export " + m[1] + m[2] + ": `check-image-pins -bake-local` passes it to docker"})
			continue
		}
		if msg := makeToolInputs(raw, l.text); msg != "" {
			out = append(out, Finding{l.line, msg})
			continue
		}
		for _, c := range buildCommands(l.text) {
			out = append(out, Finding{l.line, fmt.Sprintf("a Makefile runs %q: images are built only through `check-image-pins -bake-local`", c)})
		}
	}
	return out
}

// makeGoText finds, in a Makefile's raw text, everything that can assign
// or define GO: `GO` before an assignment operator (blanks and
// backslash-newlines between them, as make joins continuation lines),
// and `define GO` (also `override define GO`, `undefine GO`).
// makeGoLine is the allowlist: the whole physical line is one of
// `GO ?= go`, `GO := go`, `GO = go`, `override GO := go` and
// `export GO := go`, blanks around the operator free, and nothing else:
// no comment, because under .RECIPEPREFIX the line can be a recipe whose
// "comment" make expands (`GO = go # $(eval GO := ./evil)`, PR #91
// review B delta).
var (
	makeGoText = regexp.MustCompile(`\bGO\b(?:[ \t]|\\\r?\n)*(?:::?:?|\?|\+|!)?=|define(?:[ \t]|\\\r?\n)+GO\b`)
	makeGoLine = regexp.MustCompile(`^(?:GO[ \t]*[?:]?=|(?:override|export)[ \t]+GO[ \t]*:=)[ \t]*go$`)
)

// checkMakeGo applies the GO rule (#51 item 4) to a Makefile's raw text,
// before any quoting, comment or continuation handling: make images runs
// `$(GO) run ./tools/check-image-pins -bake-local`, so GO must be `go`.
// After three rounds of parser holes (#49 point 8, the 51-4 plan, PR #91
// review A), the rule is an allowlist that fails closed instead of a
// model of make's syntax: every match of makeGoText is a finding unless
// it lies on a makeGoLine. This over-reports, by design: a recipe's
// `GO=go cmd`, a `$(eval GO := go)` and a comment that mentions a GO
// assignment are reported too. Comments get no exemption: make expands
// `$(eval …)` in a tab-led `#` line (a recipe, whose `#` is the
// shell's), and .RECIPEPREFIX can make any line a recipe. An
// allowlisted line after a line that ends in a backslash is a
// continuation and is reported as well.
//
// Like every Makefile rule here, this is a fast filter, not a proof
// (maintainer decision on PR #91, 6865260080): a name built without the
// text GO (`G$ O := x`, `$ ` being the empty variable), a generated or
// remade include, and a name quoted for a sub-make (`G""O=x`) are not
// caught. TestMakefileKnownLimits pins these; review owns Makefile
// changes (second-review), and no CI image build runs make.
func checkMakeGo(src []byte) []Finding {
	text := string(src)
	lines := strings.Split(text, "\n")
	continued := func(i int) bool { return i > 0 && strings.HasSuffix(strings.TrimSuffix(lines[i-1], "\r"), `\`) }
	var out []Finding
	reported := map[int]bool{}
	for _, m := range makeGoText.FindAllStringIndex(text, -1) {
		i := strings.Count(text[:m[0]], "\n")
		if reported[i] {
			continue
		}
		if !continued(i) && makeGoLine.MatchString(lines[i]) {
			continue
		}
		reported[i] = true
		out = append(out, Finding{i + 1, "a Makefile may set GO only in a line that is exactly `GO ?= go`, `GO := go`, `GO = go`, `override GO := go` or `export GO := go` (no comment); any other text that sets or defines GO is reported (got " + strconv.Quote(lines[i]) + "): `make images` runs `$(GO) run ./tools/check-image-pins`"})
	}
	return out
}

// makeDockerEnv and makeSetEnv find the passEnv variables in a Makefile
// line: any DOCKER_CONFIG, DOCKER_HOST or DOCKER_CONTEXT; PATH or HOME
// before an assignment operator (`PATH :=`, `images: PATH +=`,
// `env HOME=x`), or after export, unexport, override or define.
var (
	makeDockerEnv = regexp.MustCompile(`\bDOCKER_(?:CONFIG|HOST|CONTEXT)\b`)
	makeSetEnv    = regexp.MustCompile(`\b(PATH|HOME)\s*(?::{1,3}|[?+!])?=|\b(?:export|unexport|override|define)\b[^=#]*?\b(PATH|HOME)\b`)
)

// The Makefile forms of #49 point 8.
var (
	makeShell    = regexp.MustCompile(`(?:^|[^\w.])(SHELL|\.SHELLFLAGS)\s*(?::{1,3}|[?+!])?=|\b(?:export|unexport|override|define)\b[^=#]*?(?:^|[^\w.])(SHELL|\.SHELLFLAGS)\b`)
	makeGoEnv    = regexp.MustCompile(`\b(GOFLAGS|GOENV|GOWORK)\s*(?::{1,3}|[?+!])?=|\b(?:export|unexport|override|define)\b[^=#]*?\b(GOFLAGS|GOENV|GOWORK)\b`)
	makeInclude  = regexp.MustCompile(`^\s*(?:-|s)?include\s+(.*)$`)
	makeVarName  = regexp.MustCompile(`([^\s=:?+!;#]+)\s*(?::{1,3}|[?+!])?=`)
	makeDirectve = regexp.MustCompile(`\b(?:export|unexport|override|define|undefine)\s+([^=#]*)`)
)

// makeToolInputs returns the finding for one Makefile line under the
// rules of #49 point 8, or "". raw is the logical line with shell quoting
// removed, so the SHELL, GO* and computed-name rules see `SHE""LL`; text
// is the same line before quote removal, which the include rule reads
// (#92).
func makeToolInputs(raw, text string) string {
	if m := makeShell.FindStringSubmatch(raw); m != nil {
		return "a Makefile may not set " + m[1] + m[2] + ": every recipe, `check-image-pins -bake-local` included, would run through it"
	}
	if m := makeGoEnv.FindStringSubmatch(raw); m != nil {
		return "a Makefile may not set or export " + m[1] + m[2] + ": it changes how `go run` builds `check-image-pins` itself"
	}
	if m := makeInclude.FindStringSubmatch(text); m != nil {
		for _, f := range strings.Fields(m[1]) {
			if !literalInclude(f) {
				return "a Makefile may include only a relative path of letters, digits, ., _, - and / ending in .mk, not under ../ and not in a skipped directory (got " + strconv.Quote(f) + ")"
			}
		}
	}
	noShellVars := strings.ReplaceAll(raw, "$$", "")
	var names []string
	for _, m := range makeVarName.FindAllStringSubmatch(noShellVars, -1) {
		names = append(names, m[1])
	}
	for _, m := range makeDirectve.FindAllStringSubmatch(noShellVars, -1) {
		names = append(names, strings.Fields(m[1])...)
	}
	// A name with `)` or `}` ends a function call with a literal
	// argument, as in `$(eval $(firstword GO) := x)` (#91 round 2).
	for _, n := range names {
		if strings.ContainsAny(n, "$)}") {
			return "a Makefile may not compute a variable name (" + strconv.Quote(n) + "): the check cannot see which variable it sets"
		}
	}
	return ""
}

// makeIncludeField is the allowlist for one include path, matched on the
// text as written (#92 round 2).
var makeIncludeField = regexp.MustCompile(`^[A-Za-z0-9._/-]+\.mk$`)

// literalInclude reports whether an include path, as written, is a
// relative path of letters, digits, `.`, `_`, `-` and `/` ending in .mk,
// not under ../ and not in a skipped directory. Every other path is
// reported by CheckMakefile and readMake, whatever make would do with it.
func literalInclude(f string) bool {
	return makeIncludeField.MatchString(f) && !skippedPath(f)
}

// skippedPath reports whether a root-relative path is inside a directory
// the walk skips.
func skippedPath(p string) bool {
	p = path.Clean(strings.TrimPrefix(p, "./"))
	for s := range skipPaths {
		if p == s || strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return strings.HasPrefix(p, "../") || path.IsAbs(p)
}

type makeLine struct {
	line int
	text string
}

// makeLogicalLines joins backslash continuations.
func makeLogicalLines(src []byte) []makeLine {
	var out []makeLine
	var cur *makeLine
	for i, raw := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimRight(raw, " \t")
		body := strings.TrimSuffix(trimmed, `\`)
		if cur == nil {
			out = append(out, makeLine{line: i + 1, text: body})
			cur = &out[len(out)-1]
		} else {
			cur.text += " " + strings.TrimSpace(body)
		}
		if !strings.HasSuffix(trimmed, `\`) {
			cur = nil
		}
	}
	return out
}

// CheckScriptText reports the build commands in a script, by line. Lines
// inside an open ( or [ are read as one with the line that opens it, so
// a list split over lines matches (#49 point 3).
func CheckScriptText(src []byte) []Finding {
	var out []Finding
	for _, l := range bracketLines(makeLogicalLines(src)) {
		for _, c := range buildCommands(l.text) {
			out = append(out, Finding{l.line, fmt.Sprintf("runs %q: images are built only through make images or the checked docker/bake-action step", c)})
		}
	}
	return out
}

// bracketLines joins each line inside an open ( or [ to the line that
// opened it.
func bracketLines(lines []makeLine) []makeLine {
	var out []makeLine
	depth := 0
	for _, l := range lines {
		if depth > 0 {
			out[len(out)-1].text += "\n" + l.text
		} else {
			out = append(out, l)
		}
		for _, c := range normalizeShell(l.text) {
			switch c {
			case '(', '[':
				depth++
			case ')', ']':
				depth = max(depth-1, 0)
			}
		}
	}
	return out
}
