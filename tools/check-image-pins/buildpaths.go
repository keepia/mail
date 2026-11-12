package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// normalizeShell lower-cases text, drops quoting characters and joins
// backslash-continued lines.
func normalizeShell(text string) string {
	text = strings.ReplaceAll(text, "\\\n", " ")
	return strings.ToLower(shellQuoting.Replace(text))
}

// buildCommands returns the image build commands in shell text: docker
// build, docker image build, docker builder build, any buildx
// build/bake/b (also as the docker-buildx plugin binary), buildctl, and
// podman or buildah build.
func buildCommands(text string) []string {
	words := shellSplit.Split(normalizeShell(text), -1)
	var found []string
	at := func(i int) string {
		if i < len(words) {
			return words[i]
		}
		return ""
	}
	for i, w := range words {
		base := w[strings.LastIndex(w, "/")+1:]
		switch {
		case base == "docker" && at(i+1) == "build":
			found = append(found, "docker build")
		case base == "docker" && (at(i+1) == "image" || at(i+1) == "builder") && at(i+2) == "build":
			found = append(found, "docker "+at(i+1)+" build")
		case (base == "buildx" || base == "docker-buildx") && (at(i+1) == "build" || at(i+1) == "bake" || at(i+1) == "b"):
			found = append(found, "buildx "+at(i+1))
		case base == "buildctl" || base == "buildctl-daemonless.sh":
			found = append(found, "buildctl")
		case (base == "podman" || base == "buildah") && (at(i+1) == "build" || at(i+1) == "bud"):
			found = append(found, base+" build")
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
func CheckMakefile(src []byte) []Finding {
	var out []Finding
	for _, l := range makeLogicalLines(src) {
		n := normalizeShell(l.text)
		if strings.Contains(n, "buildx") {
			out = append(out, Finding{l.line, "a Makefile may not mention buildx or BUILDX_ variables: images are built only through `check-image-pins -bake-local`"})
			continue
		}
		for _, c := range buildCommands(l.text) {
			out = append(out, Finding{l.line, fmt.Sprintf("a Makefile runs %q: images are built only through `check-image-pins -bake-local`", c)})
		}
	}
	return out
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
