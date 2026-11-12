package main

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The workflow side of rule 5 (#43, round 4). A workflow builds images
// only through one docker/bake-action step per job, in this shape:
//
//	env:                      # job level, the only env of the job
//	  BAKE_TARGET: <literal or ${{ matrix.* }}>
//	  PLATFORM:    <literal or ${{ matrix.* }}>
//	  BAKE_SET:    <cache-from/cache-to lines; matrix.*, github.event_name>
//	steps:
//	  - run: GOENV=off GOFLAGS= GOWORK=off go run ./tools/check-image-pins -build "$BAKE_TARGET" -build-set "$BAKE_SET"
//	  - id: build
//	    uses: docker/bake-action@<sha> # vX.Y.Z
//	    with: {source: ., targets: ${{ env.BAKE_TARGET }}, set: ${{ env.BAKE_SET }}, …}
//	  - id: verify
//	    env: {BAKE_METADATA: ${{ steps.build.outputs.metadata }}}
//	    run: GOENV=off GOFLAGS= GOWORK=off go run ./tools/check-image-pins -verify-built
//	  - env: {VERIFIED_IMAGE: ${{ steps.verify.outputs.image }}}
//	    run: … image-test … "$VERIFIED_IMAGE"   # tests the verified image ID
//	  - env: {BAKE_METADATA: ${{ steps.build.outputs.metadata }}}
//	    run: GOENV=off GOFLAGS= GOWORK=off go run ./tools/check-image-pins -verify-built -save "$RUNNER_TEMP/image.tar"
//
// Build mode checks what the build step resolves; verify mode checks
// that the images the job tests and saves are that build's output. A
// step that tests, saves, pushes or tags the image (in its run text, a
// script it names or a local action it uses) comes right after a verify
// step. Tests take the verified image ID from that step's output, and a
// save goes through -verify-built -save, which checks the saved tar
// itself, so a re-tag after verify cannot change what is tested or saved
// (#46, B N1). Any other image build (a run step or script with docker
// build, buildx build/bake, a Compose build, a build action, a remote
// reusable workflow, a composite action that builds) is reported, and so
// is any other write to GITHUB_ENV or GITHUB_PATH in the job (#46, B N2).

const (
	bakeTargetExpr = "${{ env.BAKE_TARGET }}"
	bakeSetExpr    = "${{ env.BAKE_SET }}"
	bakeStepID     = "build"
	// goRunPrefix runs the tool with the module's own build inputs: no
	// GOFLAGS (-overlay, -toolexec, -modfile), no go.work and no go env
	// file, whatever an earlier step wrote to GITHUB_ENV (#46, B N2). An
	// empty GOFLAGS alone would fall back to the go env file, so GOENV=off
	// is needed as well.
	goRunPrefix    = "GOENV=off GOFLAGS= GOWORK=off "
	bakeCheckRun   = goRunPrefix + `go run ./tools/check-image-pins -build "$BAKE_TARGET" -build-set "$BAKE_SET"`
	verifyRun      = goRunPrefix + "go run ./tools/check-image-pins -verify-built"
	verifyEnvValue = "${{ steps.build.outputs.metadata }}"
	// verifiedImageEnv is the env a test step reads the verified image ID
	// from: ${{ steps.<verify step id>.outputs.image }}.
	verifiedImageEnv = "VERIFIED_IMAGE"
)

// verifySaveRun is the verify step that also saves the image.
var verifySaveRun = regexp.MustCompile(`^` + regexp.QuoteMeta(verifyRun) + ` -save "\$RUNNER_TEMP/[A-Za-z0-9._-]+\.tar"$`)

// bakeActionKeys are the docker/bake-action inputs a step may use. Not
// allowed, among others: files, workdir, vars (they change the
// definition), github-token (remote definitions only), and sbom and
// provenance: a value such as generator=<image> becomes an attest key
// that build mode never resolves, so an unpinned generator image would
// run during the build (#46, A2). bake-action passes neither flag when
// the input is absent.
var bakeActionKeys = map[string]bool{
	"source": true, "targets": true, "set": true, "load": true, "push": true,
	"no-cache": true, "pull": true,
}

// envFileLines are the only lines of a job that builds with bake that
// may name GITHUB_ENV or GITHUB_PATH, by the file they are in ("" for a
// run step's own text): the commit time for reproducible layers, and
// the anonymous Docker client config of scripts/ci-docker-mirror.sh.
var envFileLines = map[string]map[string]bool{
	"": {`echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >>"$GITHUB_ENV"`: true},
	"scripts/ci-docker-mirror.sh": {
		`if [ -n "${GITHUB_ENV:-}" ]; then`:                   true,
		`echo "DOCKER_CONFIG=$DOCKER_CONFIG" >>"$GITHUB_ENV"`: true,
	},
}

// refText is a file a command names, relative to the root, and its text.
type refText struct {
	path, text string
}

// resolver returns the files a command text runs (see referencedTexts).
// nil resolves nothing (single-file fixtures).
type resolver func(text string) []refText

// bakeEnvKeys are the env keys a job that builds with bake may set at
// job or workflow level: the shared target and --set lines, and PLATFORM
// (a bake variable that only sets platforms; build mode resolves with
// it).
var bakeEnvKeys = map[string]bool{"BAKE_TARGET": true, "BAKE_SET": true, "PLATFORM": true}

// bakeSetAttrs are the attributes a BAKE_SET line may set: the layer
// cache, which build mode restricts to this job's own gha scope.
var bakeSetAttrs = map[string]bool{"cache-from": true, "cache-to": true}

var (
	ghExpr      = regexp.MustCompile(`\$\{\{(.*?)\}\}`)
	exprString  = regexp.MustCompile(`'(?:[^']|'')*'`)
	exprIdent   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.-]*`)
	exprAllowed = map[string]bool{"github.event_name": true, "format": true, "true": true, "false": true, "null": true}
)

// exprProblem returns the first context a GitHub expression in v reads
// that is not matrix.* or github.event_name (review B delta 2, D3: a
// BAKE_SET value from github.event.* would be attacker-controlled), or "".
func exprProblem(v string) string {
	for _, m := range ghExpr.FindAllStringSubmatch(v, -1) {
		body := exprString.ReplaceAllString(m[1], "")
		for _, id := range exprIdent.FindAllString(body, -1) {
			if exprAllowed[id] || strings.HasPrefix(id, "matrix.") {
				continue
			}
			return id
		}
	}
	return ""
}

// setLineAttr returns the attribute a `--set` line sets: the part of its
// key after the last dot, with GitHub expressions in the key masked. It
// returns "" when the attribute itself is not literal.
func setLineAttr(line string) string {
	masked := ghExpr.ReplaceAllString(line, "EXPR")
	key, _, ok := strings.Cut(masked, "=")
	if !ok {
		return ""
	}
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return ""
	}
	attr := strings.TrimSpace(key[i+1:])
	if strings.Contains(attr, "EXPR") {
		return ""
	}
	return attr
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedBool(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// isVerifyStep reports whether a step is exactly a verify step: plain,
// or with -save.
func isVerifyStep(step map[string]any) bool {
	run, _ := step["run"].(string)
	run = strings.TrimSpace(run)
	env, _ := asMap(step["env"])
	_, cont := step["continue-on-error"]
	return (run == verifyRun || verifySaveRun.MatchString(run)) && len(env) == 1 && env["BAKE_METADATA"] == verifyEnvValue && !cont
}

// stepTexts are what a step runs: its own run text (path ""), then every
// file that text names and the action.yml of a local action it uses,
// followed recursively by resolve.
func stepTexts(step map[string]any, resolve resolver) []refText {
	run, _ := step["run"].(string)
	texts := []refText{{"", run}}
	ref := run
	if uses, _ := step["uses"].(string); strings.HasPrefix(uses, "./") {
		u := strings.TrimSuffix(uses, "/")
		ref += "\n" + u + "/action.yml " + u + "/action.yaml"
	}
	if resolve != nil {
		texts = append(texts, resolve(ref)...)
	}
	return texts
}

// imageUse describes what step texts do with the built image: run
// image-test, or docker save, push or tag (#46, A3).
type imageUse struct {
	test bool
	uses []string
}

func (u imageUse) any() bool { return u.test || len(u.uses) > 0 }

func usesImage(texts []refText) imageUse {
	var u imageUse
	for _, t := range texts {
		if strings.Contains(normalizeShell(t.text), "image-test") {
			u.test = true
		}
		u.uses = append(u.uses, imageUses(t.text)...)
	}
	return u
}

// envFileWrites returns the lines of texts that name GITHUB_ENV or
// GITHUB_PATH, other than envFileLines (#46, B N2): such a write
// reaches every later step of the job, the check and verify steps
// included.
func envFileWrites(texts []refText) []string {
	var out []string
	for _, t := range texts {
		for _, l := range strings.Split(t.text, "\n") {
			l = strings.TrimSpace(l)
			n := normalizeShell(l)
			if strings.HasPrefix(l, "#") {
				continue // a comment line (shell, Python, YAML)
			}
			if (strings.Contains(n, "github_env") || strings.Contains(n, "github_path")) && !envFileLines[t.path][l] {
				where := "run"
				if t.path != "" {
					where = t.path
				}
				out = append(out, where+": "+l)
			}
		}
	}
	return out
}

// checkJobBuilds applies the workflow side of rule 5 to one job and
// returns the job's run texts (for the scripts they reference).
func checkJobBuilds(line int, job string, wfEnv any, j map[string]any, resolve resolver, add func(int, string, ...any)) []string {
	var runs []string
	if u, ok := j["uses"].(string); ok && !strings.HasPrefix(u, "./") {
		add(line, "job %s calls the remote reusable workflow %s: the check cannot read what it builds", job, u)
	}
	steps, _ := j["steps"].([]any)
	bakeAt := -1
	var envWrites []string
	for i, s := range steps {
		step, ok := asMap(s)
		if !ok {
			continue
		}
		for _, w := range envFileWrites(stepTexts(step, resolve)) {
			envWrites = append(envWrites, fmt.Sprintf("step %d, %s", i+1, w))
		}
		if run, ok := step["run"].(string); ok {
			runs = append(runs, run)
			for _, c := range buildCommands(run) {
				add(line, "job %s: step %d runs %q: images are built only by the checked docker/bake-action step", job, i+1, c)
			}
		}
		uses, _ := step["uses"].(string)
		switch {
		case strings.HasPrefix(uses, "docker/bake-action@"):
			if bakeAt >= 0 {
				add(line, "job %s: a second docker/bake-action step; one per job", job)
			}
			bakeAt = i
			checkBakeStep(line, job, i, steps, step, add)
		case isBuildAction(uses):
			add(line, "job %s: step %d uses %s, which builds images outside the checked docker/bake-action step", job, i+1, uses)
		case strings.HasPrefix(uses, "./") && !strings.HasPrefix(uses, "./.github/actions/") && !strings.HasPrefix(uses, "./.github/workflows/"):
			add(line, "job %s: step %d uses the local action %s outside .github/actions, which the check does not read", job, i+1, uses)
		}
	}
	if bakeAt < 0 {
		return runs
	}
	for _, w := range envWrites {
		add(line, "job %s: %s: a job that builds with bake may not write GITHUB_ENV or GITHUB_PATH (only SOURCE_DATE_EPOCH): it would reach the check and verify steps", job, w)
	}
	// After the build, every step that tests, saves, pushes or tags the
	// image must come right after a verify step. A test reads the image
	// ID that verify step put out, and a save is the verify step's own
	// -save.
	for i := bakeAt + 1; i < len(steps); i++ {
		step, _ := asMap(steps[i])
		texts := stepTexts(step, resolve)
		u := usesImage(texts)
		if !u.any() {
			continue
		}
		prev, _ := asMap(steps[i-1])
		if !isVerifyStep(prev) || prev["if"] != step["if"] {
			add(line, "job %s: step %d tests, saves, pushes or tags the image; the step right before must be `run: %s` with env BAKE_METADATA: %s and the same if", job, i+1, verifyRun, verifyEnvValue)
		}
		if slices.Contains(u.uses, "docker save") {
			add(line, "job %s: step %d runs docker save: save the image with `run: %s -save \"$RUNNER_TEMP/<name>.tar\"`, which checks the saved tar", job, i+1, verifyRun)
		}
		if u.test {
			id, _ := prev["id"].(string)
			env, _ := asMap(step["env"])
			want := "${{ steps." + id + ".outputs.image }}"
			reads := false
			for _, t := range texts {
				reads = reads || strings.Contains(normalizeShell(t.text), strings.ToLower(verifiedImageEnv))
			}
			if id == "" || env[verifiedImageEnv] != want || !reads {
				add(line, "job %s: step %d tests the image; it must test the verified image ID: an id on the verify step before it, env %s: ${{ steps.<that id>.outputs.image }}, and $%s in the command", job, i+1, verifiedImageEnv, verifiedImageEnv)
			}
		}
	}
	for _, scope := range []struct {
		name string
		env  any
	}{{"workflow", wfEnv}, {"job", j["env"]}} {
		if scope.env == nil {
			continue
		}
		env, ok := asMap(scope.env)
		if !ok {
			add(line, "job %s: the %s env is not a mapping", job, scope.name)
			continue
		}
		for _, k := range sortedKeys(env) {
			if !bakeEnvKeys[k] {
				add(line, "job %s: %s env %s is not allowed in a job that builds with bake (allowed: %s)", job, scope.name, k, strings.Join(sortedBool(bakeEnvKeys), ", "))
				continue
			}
			s, ok := env[k].(string)
			if !ok {
				add(line, "job %s: %s env %s is not a string", job, scope.name, k)
				continue
			}
			if id := exprProblem(s); id != "" {
				add(line, "job %s: %s env %s reads %s; only literals, matrix.* and github.event_name are allowed", job, scope.name, k, id)
			}
		}
		if scope.name == "job" {
			checkBakeSetEnv(line, job, env["BAKE_SET"], add)
		}
	}
	return runs
}

// checkBakeStep checks the bake-action step, the check step before it,
// and its id.
func checkBakeStep(line int, job string, i int, steps []any, step map[string]any, add func(int, string, ...any)) {
	with, _ := asMap(step["with"])
	for _, k := range sortedKeys(with) {
		if !bakeActionKeys[k] {
			add(line, "job %s: docker/bake-action input %q is not allowed: it can change the definition the check resolves", job, k)
		}
	}
	if with["source"] != "." {
		add(line, "job %s: docker/bake-action needs source: . (got %v)", job, with["source"])
	}
	if with["targets"] != bakeTargetExpr {
		add(line, "job %s: docker/bake-action targets must be %s (got %v), shared with the check step", job, bakeTargetExpr, with["targets"])
	}
	if set, ok := with["set"]; ok && set != bakeSetExpr {
		add(line, "job %s: docker/bake-action set must be %s (got %q), shared with the check step", job, bakeSetExpr, set)
	}
	if _, ok := step["env"]; ok {
		add(line, "job %s: the docker/bake-action step has its own env; set build inputs at job level (%s)", job, strings.Join(sortedBool(bakeEnvKeys), ", "))
	}
	if step["id"] != bakeStepID {
		add(line, "job %s: the docker/bake-action step needs id: %s (the verify step reads its metadata)", job, bakeStepID)
	}
	prev := map[string]any{}
	if i > 0 {
		prev, _ = asMap(steps[i-1])
	}
	run, _ := prev["run"].(string)
	_, prevEnv := prev["env"]
	_, prevIf := prev["if"]
	_, prevCont := prev["continue-on-error"]
	if strings.TrimSpace(run) != bakeCheckRun || prevEnv || prevIf || prevCont {
		add(line, "job %s: the step right before docker/bake-action must be exactly `run: %s`, without env, if or continue-on-error", job, bakeCheckRun)
	}
}

// checkBakeSetEnv checks the BAKE_SET lines of a job: only cache-from and
// cache-to, and a literal cache value only of type=gha (build mode checks
// the resolved value, including what an expression expands to).
func checkBakeSetEnv(line int, job string, v any, add func(int, string, ...any)) {
	if v == nil {
		return
	}
	s, ok := v.(string)
	if !ok {
		add(line, "job %s: BAKE_SET is not a string", job)
		return
	}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		attr := setLineAttr(l)
		if !bakeSetAttrs[attr] {
			add(line, "job %s: BAKE_SET line %q sets %q; only %s are allowed", job, l, attr, strings.Join(sortedBool(bakeSetAttrs), ", "))
			continue
		}
		_, value, _ := strings.Cut(ghExpr.ReplaceAllString(l, "EXPR"), "=")
		if value != "" && !strings.Contains(value, "EXPR") && !strings.HasPrefix(value, "type=gha,") && value != "type=gha" {
			add(line, "job %s: BAKE_SET line %q: the cache must be type=gha", job, l)
		}
	}
}

// CheckAction checks a composite action (action.yml): its steps may not
// build images (no build command in run, no build action in uses, no
// bake-action). It returns the run texts.
func CheckAction(src []byte) ([]Finding, []string, error) {
	docs, err := parseYAML(src)
	if err != nil {
		return nil, nil, err
	}
	var out []Finding
	var runs []string
	if len(docs) != 1 {
		return []Finding{{0, "an action file must hold exactly one YAML document"}}, nil, nil
	}
	top := root(docs[0])
	runsNode, k := mappingValue(top, "runs")
	if runsNode == nil {
		return nil, nil, nil
	}
	var r map[string]any
	if err := runsNode.Decode(&r); err != nil {
		return nil, nil, err
	}
	if using, _ := r["using"].(string); strings.HasPrefix(strings.ToLower(using), "docker") {
		out = append(out, Finding{k.Line, "a Docker container action builds or pulls an image the check does not read"})
	}
	steps, _ := r["steps"].([]any)
	for i, s := range steps {
		step, ok := asMap(s)
		if !ok {
			continue
		}
		if run, ok := step["run"].(string); ok {
			runs = append(runs, run)
			for _, c := range buildCommands(run) {
				out = append(out, Finding{k.Line, "step " + strconv.Itoa(i+1) + " runs \"" + c + "\": images are built only by the checked docker/bake-action step"})
			}
		}
		if uses, _ := step["uses"].(string); isBuildAction(uses) {
			out = append(out, Finding{k.Line, "step " + strconv.Itoa(i+1) + " uses " + uses + ", which builds images outside the checked docker/bake-action step"})
		}
	}
	return out, runs, nil
}
