package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// commands splits text into commands of words (normalised).
func commands(text string) [][]string {
	var out [][]string
	for _, c := range commandSplit.Split(normalizeShell(text), -1) {
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
	"save": true, "push": true, "tag": true,
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
// `watch`, or any subcommand with --build (up, run, create).
func composeBuild(rest []string) string {
	sub, after := subcommand(rest)
	switch {
	case sub == "build" || sub == "watch":
		return "compose " + sub
	case sub != "" && slices.Contains(after, "--build"):
		return "compose " + sub + " --build"
	}
	return ""
}

// buildCommands returns the image build commands in a text: build,
// image build and builder build of docker, podman and nerdctl; any buildx
// build/bake/b (also as the docker-buildx plugin binary); Compose builds
// (`docker compose build`, `… up --build`, `docker-compose build`,
// `podman-compose`, `nerdctl compose`); buildctl; and buildah build.
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
// and tag, also as `image save|push|tag`.
func imageUses(text string) []string {
	var found []string
	for _, words := range commands(text) {
		for i, w := range words {
			base := w[strings.LastIndex(w, "/")+1:]
			if !engines[base] {
				continue
			}
			sub, after := subcommand(words[i+1:])
			if sub == "image" {
				sub, _ = subcommand(after)
			}
			if sub == "save" || sub == "push" || sub == "tag" {
				found = append(found, "docker "+sub)
			}
		}
	}
	return found
}

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

// CheckScriptText reports the build commands in a script, by line.
func CheckScriptText(src []byte) []Finding {
	var out []Finding
	for _, l := range makeLogicalLines(src) {
		for _, c := range buildCommands(l.text) {
			out = append(out, Finding{l.line, fmt.Sprintf("runs %q: images are built only through make images or the checked docker/bake-action step", c)})
		}
	}
	return out
}

// maxReferenced bounds how many files referencedTexts follows.
const maxReferenced = 200

// referencedTexts returns the files a command text names under root
// (referencedFiles), and the files those name, recursively, each once,
// with their paths relative to root. A file that cannot be read is
// returned with its error as text, so a rule that looks for a word
// cannot pass it silently.
func referencedTexts(root, text string) []refText {
	var out []refText
	seen := map[string]bool{}
	queue := []string{text}
	for len(queue) > 0 && len(seen) < maxReferenced {
		t := queue[0]
		queue = queue[1:]
		for _, p := range referencedFiles(root, t) {
			p = filepath.Clean(p)
			if seen[p] {
				continue
			}
			seen[p] = true
			src, err := os.ReadFile(p) //nolint:gosec // p stays under root
			body := string(src)
			if err != nil {
				body = err.Error()
			}
			out = append(out, refText{filepath.ToSlash(mustRel(root, p)), body})
			queue = append(queue, body)
		}
	}
	return out
}

// referencedFiles returns the regular files under root that words of a
// command text name (`sh scripts/build`, `./scripts/x`, `bash x.txt`): a
// script runs whatever its name or extension.
func referencedFiles(root, text string) []string {
	var files []string
	for _, w := range shellSplit.Split(shellQuoting.Replace(text), -1) {
		w = strings.TrimPrefix(w, "./")
		if w == "" || strings.ContainsAny(w, "$*?=") || filepath.IsAbs(w) || strings.HasPrefix(w, "-") {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(w))
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() { //nolint:gosec // p stays under root
			files = append(files, p)
		}
	}
	return files
}
