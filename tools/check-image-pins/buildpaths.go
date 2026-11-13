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
// them in the check steps' prefix); GO set to anything but exactly `go`
// (the whole value, a trailing comment aside; any `define GO`, `GO +=`
// or `GO !=`, also after override or export, #51 item 4); an
// include of a file that is not a literal *.mk path the walk reads; and a
// variable name that is computed (`export PA$(E)TH`).
func CheckMakefile(src []byte) []Finding {
	var out []Finding
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
		if msg := makeToolInputs(raw); msg != "" {
			out = append(out, Finding{l.line, msg})
			continue
		}
		for _, c := range buildCommands(l.text) {
			out = append(out, Finding{l.line, fmt.Sprintf("a Makefile runs %q: images are built only through `check-image-pins -bake-local`", c)})
		}
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
	makeGoVar    = regexp.MustCompile(`\bGO\s*(:{1,3}|[?+!])?=([^)]*)`)
	makeGoDefine = regexp.MustCompile(`\bdefine\s+GO\b`)
	makeInclude  = regexp.MustCompile(`^\s*(?:-|s)?include\s+(.*)$`)
	makeVarName  = regexp.MustCompile(`([^\s=:?+!;#]+)\s*(?::{1,3}|[?+!])?=`)
	makeDirectve = regexp.MustCompile(`\b(?:export|unexport|override|define|undefine)\s+([^=#]*)`)
)

// makeToolInputs returns the finding for one Makefile line under the
// rules of #49 point 8, or "".
func makeToolInputs(raw string) string {
	if m := makeShell.FindStringSubmatch(raw); m != nil {
		return "a Makefile may not set " + m[1] + m[2] + ": every recipe, `check-image-pins -bake-local` included, would run through it"
	}
	if m := makeGoEnv.FindStringSubmatch(raw); m != nil {
		return "a Makefile may not set or export " + m[1] + m[2] + ": it changes how `go run` builds `check-image-pins` itself"
	}
	// GO is compared as its whole value (#51 item 4): only the first word
	// let `GO := go -C ./evil` through. A make comment is cut off first,
	// but not in a recipe line (a tab first), where `#` is the shell's and
	// may be quoted (`echo "#"; GO=x make images`). The value ends at a
	// `)`, which closes `$(eval GO := …)`; in a plain assignment, text
	// after a bare `)` would be a shell syntax error in every recipe that
	// runs $(GO). += and != never give exactly `go`, and a define body is
	// not read.
	code := raw
	if !strings.HasPrefix(raw, "\t") {
		code, _, _ = strings.Cut(raw, "#")
	}
	if makeGoDefine.MatchString(code) {
		return "a Makefile may not set GO with define (its body is not read): set it only to `go` (`GO ?= go`); `make images` runs `$(GO) run ./tools/check-image-pins`"
	}
	if m := makeGoVar.FindStringSubmatch(code); m != nil {
		v := strings.TrimSpace(m[2])
		switch {
		case m[1] == "+" || m[1] == "!":
			return "a Makefile may set GO only to `go`, never with " + m[1] + "= (got " + strconv.Quote(v) + "): `make images` runs `$(GO) run ./tools/check-image-pins`"
		case v != "go":
			return "a Makefile may set GO only to `go` (got " + strconv.Quote(v) + "): `make images` runs `$(GO) run ./tools/check-image-pins`"
		}
	}
	if m := makeInclude.FindStringSubmatch(raw); m != nil {
		for _, f := range strings.Fields(m[1]) {
			if strings.ContainsAny(f, "$`*?[") || !strings.HasSuffix(f, ".mk") || skippedPath(f) {
				return "a Makefile may include only literal *.mk files the check reads (got " + strconv.Quote(f) + ")"
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
	for _, n := range names {
		if strings.Contains(n, "$") {
			return "a Makefile may not compute a variable name (" + strconv.Quote(n) + "): the check cannot see which variable it sets"
		}
	}
	return ""
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
