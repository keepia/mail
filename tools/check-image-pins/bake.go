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

// Rule 5 checks the bake definition as Docker resolves it, never its HCL
// lines (#43, coordinator decision G8/G17 in round 4): the check is part
// of every build invocation and checks what that invocation builds.
//
//   - Local mode (`-bake-local`, the only local build path: make images):
//     the tool builds the bake argv itself (the root's default files,
//     --set lines only from its typed options, a cleaned environment),
//     resolves --print with exactly that argv, checks it, and then runs
//     `docker buildx bake` with the same argv and environment.
//   - Build mode (`-build`, in CI right before docker/bake-action): the
//     build step's targets, --set lines and environment, as bake-action
//     runs them. After the build, `-verify-built` checks that the images
//     the job tests and uploads are the ones that build produced.
//   - Repository mode (make image-pins): the default files in a cleaned
//     environment, plus a sentinel run for bake variables. Best effort for
//     value-conditional expressions (see the threat model in
//     .claude/rules/docker.md); the two modes above are authoritative.

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

// passEnv are the variables a cleaned bake environment keeps: what the
// docker CLI needs to find its plugin and its daemon. None of them is
// read by bake's definition.
var passEnv = []string{"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"}

// bakeTarget is a resolved bake target: the fields rule 5 reads, and the
// set of keys bake printed.
type bakeTarget struct {
	Context          string              `json:"context"`
	Contexts         map[string]string   `json:"contexts"`
	Dockerfile       string              `json:"dockerfile"`
	DockerfileInline string              `json:"dockerfile-inline"`
	Args             map[string]*string  `json:"args"`
	CacheFrom        []map[string]string `json:"cache-from"`
	CacheTo          []map[string]string `json:"cache-to"`
	Secret           []map[string]string `json:"secret"`
	Network          *string             `json:"network"`
	Entitlements     []string            `json:"entitlements"`
	Tags             []string            `json:"tags"`
	Labels           map[string]string   `json:"labels"`
	Output           []map[string]string `json:"output"`
	Attest           []map[string]string `json:"attest"`
	keys             []string
}

// targetKeys are the resolved keys rule 5 accepts in every mode (the ones
// it checks below, or that cannot change what is built from which
// sources). Every other key is reported: output, ssh, entitlements, call,
// attest and whatever bake adds later.
var targetKeys = map[string]bool{
	"context": true, "contexts": true, "dockerfile": true, "dockerfile-inline": true,
	"args": true, "labels": true, "tags": true, "platforms": true, "target": true,
	"cache-from": true, "cache-to": true, "secret": true, "network": true, "entitlements": true,
}

// bake runs `docker buildx bake` in dir. files, when set, are passed with
// --file. env, when not nil, replaces the environment. bin, when set, is
// the docker binary's absolute path (local mode resolves it once, so the
// resolve and the build run the same binary); otherwise each run looks
// docker up in PATH.
type bake struct {
	dir   string
	files []string
	env   []string
	bin   string
}

// docker is the program a bake run executes.
func (b bake) docker() string {
	if b.bin != "" {
		return b.bin
	}
	return "docker"
}

// cleanEnv is a cleaned bake environment: passEnv from ours, plus the
// given variables. Nothing else from the caller (no BUILDX_*, no HCL
// variable) reaches bake.
func cleanEnv(vars map[string]string) []string {
	// Never nil: exec.Cmd with a nil Env inherits the whole environment.
	env := []string{}
	for _, k := range passEnv {
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

// argv is the full docker argument list of a bake run with args.
func (b bake) argv(args ...string) []string {
	full := []string{"buildx", "bake"}
	for _, f := range b.files {
		full = append(full, "--file", f)
	}
	return append(full, args...)
}

func (b bake) run(args ...string) ([]byte, error) {
	full := b.argv(append([]string{"--progress=quiet"}, args...)...)
	cmd := exec.Command(b.docker(), full...) //nolint:gosec // the docker CLI; file names are buildx's default names, --set lines come from typed options, target names match bakeTargetName and follow --
	cmd.Dir = b.dir
	cmd.Env = b.env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", b.docker(), strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
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

// printArgs are the arguments of a --print run with these --set lines
// and targets.
func printArgs(sets, names []string) []string {
	args := []string{"--print"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	args = append(args, "--")
	return append(args, names...)
}

// print resolves the named targets with the given --set values.
func (b bake) print(sets, names []string) (map[string]bakeTarget, error) {
	out, err := b.run(printArgs(sets, names)...)
	if err != nil {
		return nil, err
	}
	var printed struct {
		Target map[string]bakeTarget `json:"target"`
	}
	if err := json.Unmarshal(out, &printed); err != nil {
		return nil, fmt.Errorf("bake --print output does not parse: %w", err)
	}
	var raw struct {
		Target map[string]map[string]json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("bake --print output does not parse: %w", err)
	}
	for n, t := range printed.Target {
		for k := range raw.Target[n] {
			t.keys = append(t.keys, k)
		}
		sort.Strings(t.keys)
		printed.Target[n] = t
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

// rootBakeFiles lists buildx's default files present at root, in order.
func rootBakeFiles(root string) []string {
	var files []string
	for _, name := range defaultBakeFiles {
		if st, err := os.Stat(filepath.Join(root, name)); err == nil && st.Mode().IsRegular() { //nolint:gosec // a fixed default file name under root
			files = append(files, name)
		}
	}
	return files
}

// targetPolicy is what a mode allows beyond rule 5's fixed checks.
type targetPolicy struct {
	// cacheScope, when set, allows cache-from and cache-to entries of
	// type=gha with exactly this scope (build mode); otherwise no cache.
	cacheScope string
	// secretSrc, when set, allows exactly one secret: id=ca from this file
	// (local mode, -ca).
	secretSrc string
	// hostNetwork allows network=host (local mode, -host-network).
	hostNetwork bool
	// release, when set, is a build of release.yml (build mode with a
	// release- cache scope): see checkReleaseTarget.
	release *releaseBuild
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
	f, dockerfiles := CheckBakeTargets(root, targets, targetPolicy{})
	findings = append(findings, f...)

	// Every variable at a sentinel: a checked field that moves would move
	// with the build's environment too. One value per variable: a
	// condition on another specific value is not seen here (best effort);
	// the local and build modes check the real environment.
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
	// Findings that appear only with the variables at sentinels.
	base := map[string]bool{}
	for _, f := range findings {
		base[f] = true
	}
	movedFindings, _ := CheckBakeTargets(root, moved, targetPolicy{})
	for _, f := range movedFindings {
		if !base[f] {
			findings = append(findings, "with the bake variables at sentinel values: "+f)
		}
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

// buildCacheScope is the gha cache scope a build-mode target may use:
// <target>-<arch>, with the arch from the job's PLATFORM (linux/<arch>).
func buildCacheScope(target string) string {
	p := os.Getenv("PLATFORM")
	arch := p[strings.LastIndex(p, "/")+1:]
	if arch == "" {
		return ""
	}
	return target + "-" + arch
}

// checkBuildBake resolves what one build step builds: its targets and
// --set values, in the caller's environment, with buildx's own file
// lookup, as docker/bake-action runs it.
func checkBuildBake(root string, targets, sets []string) ([]string, []string) {
	names, findings := plainNames(targets)
	if len(names) == 0 {
		return append(findings, "no target to check"), nil
	}
	release, problems := releaseBuildOf(sets)
	findings = append(findings, problems...)
	if release != nil && len(names) != 1 {
		findings = append(findings, "a release build builds exactly one target")
	}
	resolved, err := bake{dir: root}.print(sets, names)
	if err != nil {
		return append(findings, "cannot resolve the build's bake definition: "+err.Error()), nil
	}
	var dockerfiles []string
	for _, n := range sortedTargetNames(resolved) {
		scope := ""
		if len(names) == 1 {
			scope = buildCacheScope(names[0])
			if release != nil && scope != "" {
				scope = "release-" + scope
			}
		}
		f, d := CheckBakeTargets(root, map[string]bakeTarget{n: resolved[n]}, targetPolicy{cacheScope: scope, release: release})
		findings = append(findings, f...)
		dockerfiles = append(dockerfiles, d...)
	}
	return findings, dockerfiles
}

func sortedTargetNames(t map[string]bakeTarget) []string {
	names := make([]string, 0, len(t))
	for n := range t {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CheckBakeTargets applies rule 5 to resolved targets: only the keys in
// targetKeys; every context a relative path inside root; no named
// contexts, no dockerfile-inline and no BUILDKIT_SYNTAX argument (it
// overrides the pinned # syntax=); cache, secret and network only as the
// mode's policy allows. It returns the findings and the Dockerfile of
// every target (a path under root), which the caller checks with the
// Dockerfile rules wherever it lives and whatever its name.
func CheckBakeTargets(root string, targets map[string]bakeTarget, policy targetPolicy) ([]string, []string) {
	var findings, dockerfiles []string
	for _, n := range sortedTargetNames(targets) {
		t := targets[n]
		bad := func(format string, a ...any) {
			findings = append(findings, fmt.Sprintf("target %q: %s", n, fmt.Sprintf(format, a...)))
		}
		for _, k := range t.keys {
			if !targetKeys[k] && (policy.release == nil || !releaseTargetKeys[k]) {
				bad("%s is not allowed: it can change how or from what the image is built", k)
			}
		}
		if policy.release != nil {
			checkReleaseTarget(bad, n, t, policy)
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
		if policy.release == nil {
			checkCache(bad, "cache-from", t.CacheFrom, policy.cacheScope)
			checkCache(bad, "cache-to", t.CacheTo, policy.cacheScope)
		}
		switch {
		case len(t.Secret) == 0:
		case policy.secretSrc != "" && len(t.Secret) == 1 && fmt.Sprint(t.Secret[0]) == fmt.Sprint(map[string]string{"id": "ca", "src": policy.secretSrc}):
		default:
			bad("secret %v is not allowed here (only id=ca from -ca in local builds)", t.Secret)
		}
		if t.Network != nil && (!policy.hostNetwork || *t.Network != "host") {
			bad("network %q is not allowed here (only host, from -host-network in local builds)", *t.Network)
		}
		// bake adds the entitlement network=host needs; nothing else.
		for _, e := range t.Entitlements {
			if !policy.hostNetwork || e != "network.host" {
				bad("entitlement %q is not allowed here (only network.host, from -host-network in local builds)", e)
			}
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

// ghaCacheKeys are the keys a gha cache entry may carry: no url, no token,
// no ref, nothing that points at another cache.
var ghaCacheKeys = map[string]bool{"type": true, "scope": true, "mode": true}

// checkCache allows only type=gha entries with exactly scope (and no
// entry at all when scope is empty): an imported cache stands in for
// build steps by their cache keys, so a foreign cache could replace any
// RUN or COPY layer and bypass every pin (review A delta 2, 1a).
func checkCache(bad func(string, ...any), attr string, entries []map[string]string, scope string) {
	for _, e := range entries {
		if scope == "" {
			bad("%s %v is not allowed here: only CI's BAKE_SET sets the cache", attr, e)
			continue
		}
		ok := e["type"] == "gha" && e["scope"] == scope
		for k := range e {
			ok = ok && ghaCacheKeys[k]
		}
		if !ok {
			bad("%s %v is not allowed: only type=gha with scope=%s and no other key", attr, e, scope)
		}
	}
}
