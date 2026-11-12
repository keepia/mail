package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule 5 checks the bake definition as Docker resolves it, not its HCL
// lines (#43 round 3, G17): the check verifies exactly the definition a
// build resolves, and no input can change that definition unless the
// check sees it too.
//
//   - Repository mode (make image-pins): the root's default bake files,
//     passed explicitly with --file, resolved in a cleaned environment,
//     once with every variable at its default and once with every
//     variable set to a sentinel. A target whose context, contexts,
//     dockerfile, dockerfile-inline or BUILDKIT_SYNTAX moves with a
//     variable is reported, because the build's environment could set it.
//   - Build mode (make image-pins-build, in CI right before the build
//     step): the exact targets, --set values and environment of that
//     build step, with buildx's own file lookup, as the build itself.
//
// Builds may only run bake through make images or docker/bake-action with
// the inputs the workflow and Makefile rules allow, so these two modes see
// every input a build can give.

// defaultBakeFiles is buildx's default file list, in the order it reads
// them (measured with buildx v0.38.1: compose.override.* and other *.hcl
// are not read).
var defaultBakeFiles = []string{
	"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml",
	"docker-bake.json", "docker-bake.hcl", "docker-bake.override.json", "docker-bake.override.hcl",
}

// bakeTargetName is a name the check passes to bake: no flag, no path.
var bakeTargetName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// variableSentinels are the sentinel values of the repository's known
// variables, chosen so bake still resolves (PLATFORM must be a platform).
// Any other variable gets defaultSentinel; if the definition then does
// not resolve, the check fails closed.
var variableSentinels = map[string]string{
	"VERSION":  "0.0.0-keepia-sentinel",
	"REGISTRY": "registry.invalid/keepia-sentinel",
	"PLATFORM": "linux/s390x",
}

const defaultSentinel = "keepia-sentinel"

// bakeTarget is the part of a resolved bake target that rule 5 reads.
type bakeTarget struct {
	Context          string             `json:"context"`
	Contexts         map[string]string  `json:"contexts"`
	Dockerfile       string             `json:"dockerfile"`
	DockerfileInline string             `json:"dockerfile-inline"`
	Args             map[string]*string `json:"args"`
}

// bake runs `docker buildx bake` in dir. files, when set, are passed with
// --file. env, when not nil, replaces the environment.
type bake struct {
	dir   string
	files []string
	env   []string
}

// cleanEnv is the environment of a repository-mode bake run: only what
// the docker CLI needs to find its buildx plugin, plus the given
// variables. Nothing else from the caller (no BUILDX_BAKE_*, no HCL
// variable) reaches bake.
func cleanEnv(vars map[string]string) []string {
	// Never nil: exec.Cmd with a nil Env inherits the whole environment.
	env := []string{}
	for _, k := range []string{"PATH", "HOME", "DOCKER_CONFIG"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range vars {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	return env
}

func (b bake) run(args ...string) ([]byte, error) {
	full := []string{"buildx", "bake", "--progress=quiet"}
	for _, f := range b.files {
		full = append(full, "--file", f)
	}
	full = append(full, args...)
	cmd := exec.Command("docker", full...) //nolint:gosec // fixed program; file names are buildx's default names, target names match bakeTargetName and follow --
	cmd.Dir = b.dir
	cmd.Env = b.env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w: %s", strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// list returns the names `bake --list=type=<kind>` prints (for targets:
// not groups).
func (b bake) list(kind string) ([]string, error) {
	out, err := b.run("--list=type=" + kind + ",format=json")
	if err != nil {
		return nil, err
	}
	var listed []struct {
		Name  string `json:"name"`
		Group bool   `json:"group"`
	}
	if err := json.Unmarshal(out, &listed); err != nil {
		return nil, fmt.Errorf("bake --list output does not parse: %w", err)
	}
	var names []string
	for _, t := range listed {
		if !t.Group {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// print resolves the named targets with the given --set values.
func (b bake) print(sets, names []string) (map[string]bakeTarget, error) {
	args := []string{"--print"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	args = append(args, "--")
	args = append(args, names...)
	out, err := b.run(args...)
	if err != nil {
		return nil, err
	}
	var printed struct {
		Target map[string]bakeTarget `json:"target"`
	}
	if err := json.Unmarshal(out, &printed); err != nil {
		return nil, fmt.Errorf("bake --print output does not parse: %w", err)
	}
	return printed.Target, nil
}

// plainNames splits names into the ones bake may be given and findings
// for the rest.
func plainNames(names []string) ([]string, []string) {
	var ok, findings []string
	for _, n := range names {
		if bakeTargetName.MatchString(n) {
			ok = append(ok, n)
		} else {
			findings = append(findings, fmt.Sprintf("target name %q is not a plain name (%s)", n, bakeTargetName))
		}
	}
	return ok, findings
}

// checkRepoBake resolves the root's default bake files (rel names) in a
// cleaned environment and applies rule 5. It returns findings and the
// Dockerfiles of every target.
func checkRepoBake(root string, files []string) ([]string, []string) {
	b := bake{dir: root, files: files, env: cleanEnv(nil)}
	listed, err := b.list("targets")
	if err != nil {
		return []string{"cannot resolve the bake definition (rule 5 needs the docker CLI with buildx): " + err.Error()}, nil
	}
	names, findings := plainNames(listed)
	if len(names) == 0 {
		return findings, nil
	}
	targets, err := b.print(nil, names)
	if err != nil {
		return append(findings, "cannot resolve the bake definition: "+err.Error()), nil
	}
	f, dockerfiles := CheckBakeTargets(root, targets)
	findings = append(findings, f...)

	// Every variable at a sentinel: a checked field that moves would move
	// with the build's environment too.
	vars, err := b.list("variables")
	if err != nil {
		return append(findings, "cannot list the bake variables: "+err.Error()), dockerfiles
	}
	if len(vars) == 0 {
		return findings, dockerfiles
	}
	sentinels := map[string]string{}
	for _, v := range vars {
		s, ok := variableSentinels[v]
		if !ok {
			s = defaultSentinel
		}
		sentinels[v] = s
	}
	moved, err := bake{dir: root, files: files, env: cleanEnv(sentinels)}.print(nil, names)
	if err != nil {
		return append(findings, fmt.Sprintf("the bake definition does not resolve with its variables (%s) at sentinel values, so the check cannot show that no variable steers context, contexts, dockerfile or BUILDKIT_SYNTAX: %v",
			strings.Join(vars, ", "), err)), dockerfiles
	}
	for _, n := range names {
		for _, field := range diffChecked(targets[n], moved[n]) {
			findings = append(findings, fmt.Sprintf("target %q: %s depends on a bake variable (%s at sentinel values); a build's environment could change it", n, field, strings.Join(vars, ", ")))
		}
	}
	return findings, dockerfiles
}

// diffChecked lists the rule-5 fields that differ between two resolutions
// of one target.
func diffChecked(a, b bakeTarget) []string {
	var d []string
	if a.Context != b.Context {
		d = append(d, "context")
	}
	if fmt.Sprint(a.Contexts) != fmt.Sprint(b.Contexts) {
		d = append(d, "contexts")
	}
	if a.Dockerfile != b.Dockerfile {
		d = append(d, "dockerfile")
	}
	if a.DockerfileInline != b.DockerfileInline {
		d = append(d, "dockerfile-inline")
	}
	if fmt.Sprint(syntaxArg(a)) != fmt.Sprint(syntaxArg(b)) {
		d = append(d, "args.BUILDKIT_SYNTAX")
	}
	return d
}

// syntaxArg returns the BUILDKIT_SYNTAX argument of a target, if any.
func syntaxArg(t bakeTarget) []string {
	var v []string
	for k, val := range t.Args {
		if strings.EqualFold(k, "BUILDKIT_SYNTAX") {
			s := "<nil>"
			if val != nil {
				s = *val
			}
			v = append(v, k+"="+s)
		}
	}
	sort.Strings(v)
	return v
}

// checkBuildBake resolves what one build step builds: its targets and
// --set values, in the caller's environment, with buildx's own file
// lookup, as docker/bake-action runs it.
func checkBuildBake(root string, targets, sets []string) ([]string, []string) {
	names, findings := plainNames(targets)
	if len(names) == 0 {
		return append(findings, "no target to check"), nil
	}
	resolved, err := bake{dir: root}.print(sets, names)
	if err != nil {
		return append(findings, "cannot resolve the build's bake definition: "+err.Error()), nil
	}
	f, dockerfiles := CheckBakeTargets(root, resolved)
	return append(findings, f...), dockerfiles
}

// CheckBakeTargets applies rule 5 to resolved targets: every context is a
// relative path inside root, and there are no named contexts, no
// dockerfile-inline and no BUILDKIT_SYNTAX argument (it overrides the
// pinned # syntax=). It returns the findings and the Dockerfile of every
// target (a path under root), which the caller checks with the Dockerfile
// rules wherever it lives and whatever its name.
func CheckBakeTargets(root string, targets map[string]bakeTarget) ([]string, []string) {
	var findings, dockerfiles []string
	names := make([]string, 0, len(targets))
	for n := range targets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := targets[n]
		bad := func(format string, a ...any) {
			findings = append(findings, fmt.Sprintf("target %q: %s", n, fmt.Sprintf(format, a...)))
		}
		if len(t.Contexts) > 0 {
			keys := make([]string, 0, len(t.Contexts))
			for k, v := range t.Contexts {
				keys = append(keys, k+"="+v)
			}
			sort.Strings(keys)
			bad("named contexts are not allowed (%s): they can pull an image or source this check does not see", strings.Join(keys, ", "))
		}
		if t.DockerfileInline != "" {
			bad("dockerfile-inline is not read by this check; use a Dockerfile")
		}
		if len(syntaxArg(t)) > 0 {
			bad("the BUILDKIT_SYNTAX argument overrides the pinned # syntax= directive")
		}
		context := t.Context
		if context == "" {
			context = "."
		}
		if !isLocalContext(context) {
			bad("context %q is not a relative path inside the repository", context)
			continue
		}
		if t.DockerfileInline != "" {
			continue
		}
		df := t.Dockerfile
		if df == "" {
			df = "Dockerfile"
		}
		if filepath.IsAbs(df) || !isLocalContext(filepath.ToSlash(df)) {
			bad("dockerfile %q is not a relative path inside the context", df)
			continue
		}
		dockerfiles = append(dockerfiles, filepath.Join(root, filepath.FromSlash(context), filepath.FromSlash(df)))
	}
	return findings, dockerfiles
}
