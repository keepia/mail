package main

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Rule 7, the release surface (#27, plan revisions 1-5): the one workflow
// that may push packages, .github/workflows/release.yml (P1, rule 6 for
// every other file), has exactly the planned shape. The rule is the
// release policy as data: releaseJobs and the exact steps of the jobs
// that hold packages: write (and of push-rehearsal, their read-only
// twin). It reports:
//
//   - P2: a job that is not in the policy and a job of the policy that is
//     missing; permissions other than the policy's, top-level other than
//     {}; a job-level `uses:` (a reusable workflow).
//   - P3, P4, P5, P9: in push, push-rehearsal, index and latest, every
//     step is exactly the policy's step at that position: the same action
//     with exactly its inputs, or a run step whose trimmed text equals one
//     fixed line, with exactly its env and id and no if, shell,
//     working-directory or continue-on-error. Nothing is resolved: a text
//     is one of the lines or it is reported. So such a job runs no
//     repository script, make target or other `go run`, defines no shell
//     function and runs no eval, sh -c, source or xargs (P5 holds by
//     construction; its messages name the form), and pushes only through
//     the bake step (by digest, BAKE_SET exactly the policy's lines, which
//     build mode resolves) and -publish-index and -move-latest.
//   - P6: `needs` and `if` of every job other than the policy's.
//   - P7: continue-on-error anywhere; a job container, services,
//     concurrency, defaults or env (env only in the bake jobs, exactly
//     BAKE_TARGET, PLATFORM, VERSION and BAKE_SET); workflow env, defaults
//     other than run.shell bash; and in release, attest and attest-assets
//     any repository code (design-system's checkReleaseJob, ported).
//   - P8: `on:` other than workflow_dispatch with the inputs dry_run
//     (boolean, default true) and version (string, default ""); the
//     workflow-level concurrency other than exactly {group: release,
//     cancel-in-progress: false}, which serialises the runs that move
//     `latest` forward (B6); a `${{ }}` in any run text; a VERSION env
//     other than ${{ needs.version.outputs.version }}.
//   - SOURCE_DATE_EPOCH required in build, push and push-rehearsal before
//     the check step (B1 M3).
//
// The rule runs on release.yml in repository mode (make image-pins);
// main's workflows hold no release.yml until #27 part 4b, so it reports
// nothing there.

// releaseWorkflowName is the one workflow file name rule 6 exempts, in
// .github/workflows and in exactly this case.
const releaseWorkflowName = "release.yml"

const (
	versionExpr      = "${{ needs.version.outputs.version }}"
	releaseDryIf     = "${{ inputs.dry_run }}"
	releaseRealIf    = "${{ !inputs.dry_run }}"
	releaseBundleIf  = "${{ !cancelled() && needs.version.result == 'success' && needs.build.result == 'success' && ((inputs.dry_run && needs.push-rehearsal.result == 'success') || (!inputs.dry_run && needs.push.result == 'success' && needs.index.result == 'success')) }}"
	indexDigestsExpr = "${{ needs.index.outputs.digests }}"
	matrixRunsOn     = "${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}"
	plainRunsOn      = "ubuntu-24.04"

	// The fixed run lines of the jobs with packages: write (P4, numbered
	// as in the plan).
	lineEpoch        = `echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >>"$GITHUB_ENV"`
	lineLogin        = `echo "$TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin`
	lineCheck        = bakeCheckRun
	lineVerifyPushed = goRunPrefix + "go run ./tools/check-image-pins -verify-pushed"
	linePublishIndex = goRunPrefix + "go run ./tools/check-image-pins -publish-index"
	lineMoveLatest   = goRunPrefix + "go run ./tools/check-image-pins -move-latest"

	// syftRun starts the SBOM step of the build job (Q1: syft by a literal
	// version through the Go module proxy).
	syftRun = "go run github.com/anchore/syft/cmd/syft@v1.57.1 "
)

// releaseJob is the policy of one job of release.yml.
type releaseJob struct {
	perms map[string]string
	needs []string
	cond  string // the exact `if`; "" for none
	// bake: build, push or push-rehearsal (job env exactly releaseBakeEnv).
	bake bool
	// steps: the exact steps (P4, P9); nil for a job checked otherwise.
	steps []stepSpec
	// outputs: the exact job outputs of a job with steps.
	outputs map[string]any
	// noRepoCode: release, attest and attest-assets (P7, design-system).
	noRepoCode bool
}

// stepSpec is one exact step: an action (uses, with) or a run step (run,
// env), with its id.
type stepSpec struct {
	uses string
	with map[string]any
	run  string
	env  map[string]any
	id   string
}

func (s stepSpec) String() string {
	if s.uses != "" {
		return fmt.Sprintf("uses %s@<sha> with %v", s.uses, s.with)
	}
	return fmt.Sprintf("run: %s (env %v, id %q)", s.run, s.env, s.id)
}

var (
	stepCheckout  = stepSpec{uses: "actions/checkout", with: map[string]any{"persist-credentials": false}}
	stepSetupGo   = stepSpec{uses: "actions/setup-go", with: map[string]any{"go-version-file": "go.mod"}}
	stepSetupBake = stepSpec{uses: "docker/setup-buildx-action", with: map[string]any{
		"buildkitd-config-inline": "[registry.\"docker.io\"]\n  mirrors = [\"mirror.gcr.io\"]",
	}}
	stepTested = stepSpec{uses: "actions/download-artifact", with: map[string]any{
		"name": "tested-${{ matrix.image }}-${{ matrix.arch }}", "path": "${{ runner.temp }}/tested",
	}}
	// The digest file of a push row; pushed.tar stays in the workspace and
	// never goes into an upload (R3).
	stepUploadDigest = stepSpec{uses: "actions/upload-artifact", with: map[string]any{
		"name": "digest-${{ matrix.image }}-${{ matrix.arch }}", "path": "${{ runner.temp }}/digest/", "if-no-files-found": "error",
	}}
	stepDigests = stepSpec{uses: "actions/download-artifact", with: map[string]any{
		"pattern": "digest-*", "path": "${{ runner.temp }}/digest", "merge-multiple": true,
	}}
	stepBake = stepSpec{uses: "docker/bake-action", id: bakeStepID, with: map[string]any{
		"source": ".", "targets": bakeTargetExpr, "set": bakeSetExpr,
	}}
	stepEpoch        = stepSpec{run: lineEpoch}
	stepLogin        = stepSpec{run: lineLogin, env: map[string]any{"TOKEN": "${{ secrets.GITHUB_TOKEN }}"}} //nolint:gosec // an expression the workflow must hold, not a credential
	stepCheck        = stepSpec{run: lineCheck}
	stepVerifyPushed = stepSpec{run: lineVerifyPushed, id: "pushed", env: map[string]any{"BAKE_METADATA": verifyEnvValue}}
	stepPublishIndex = stepSpec{run: linePublishIndex, id: "index", env: map[string]any{"VERSION": versionExpr}}
	stepMoveLatest   = stepSpec{run: lineMoveLatest, env: map[string]any{"VERSION": versionExpr, "INDEX_DIGESTS": indexDigestsExpr}}
)

var (
	pushSteps      = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepTested, stepEpoch, stepLogin, stepCheck, stepBake, stepVerifyPushed, stepUploadDigest}
	rehearsalSteps = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepTested, stepEpoch, stepCheck, stepBake, stepVerifyPushed, stepUploadDigest}
	indexSteps     = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepDigests, stepLogin, stepPublishIndex}
	latestSteps    = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepLogin, stepMoveLatest}
)

var (
	readOnly    = map[string]string{"contents": "read"}
	readPackage = map[string]string{"contents": "read", "packages": "write"}
	attestPerms = map[string]string{"id-token": "write", "attestations": "write"}
)

// releaseJobOrder lists the jobs of the policy (P2: exactly these).
var releaseJobOrder = []string{"version", "build", "push-rehearsal", "push", "index", "bundle", "attest", "attest-assets", "release", "latest"}

var releaseJobs = map[string]releaseJob{
	"version":        {perms: map[string]string{"contents": "read", "pull-requests": "read"}},
	"build":          {perms: readOnly, needs: []string{"version"}, bake: true},
	"push-rehearsal": {perms: readOnly, needs: []string{"version", "build"}, cond: releaseDryIf, bake: true, steps: rehearsalSteps},
	"push":           {perms: readPackage, needs: []string{"version", "build"}, cond: releaseRealIf, bake: true, steps: pushSteps},
	"index": {perms: readPackage, needs: []string{"version", "push"}, cond: releaseRealIf, steps: indexSteps,
		outputs: map[string]any{"digests": "${{ steps.index.outputs.digests }}"}},
	"bundle":        {perms: readOnly, needs: []string{"version", "build", "push-rehearsal", "push", "index"}, cond: releaseBundleIf},
	"attest":        {perms: attestPerms, needs: []string{"version", "index", "bundle"}, cond: releaseRealIf, noRepoCode: true},
	"attest-assets": {perms: attestPerms, needs: []string{"bundle"}, cond: releaseRealIf, noRepoCode: true},
	"release":       {perms: map[string]string{"contents": "write"}, needs: []string{"version", "bundle", "attest", "attest-assets"}, cond: releaseRealIf, noRepoCode: true},
	"latest":        {perms: readPackage, needs: []string{"version", "index", "release"}, cond: releaseRealIf, steps: latestSteps},
}

// releaseBakeSet are the exact BAKE_SET lines of the bake jobs (revision
// 2 B, revision 3 B5): the release cache of the row, and for push and
// its twin the two outputs and the provenance attestation.
func releaseBakeSet(job string) []string {
	const t, scope = "${{ matrix.image }}", "release-${{ matrix.image }}-${{ matrix.arch }}"
	if job == "build" {
		return []string{t + ".cache-to=type=gha,mode=max,scope=" + scope}
	}
	push := "true"
	if job == "push-rehearsal" {
		push = "false"
	}
	return []string{
		t + ".cache-from=type=gha,scope=" + scope,
		t + ".output=type=image,push-by-digest=true,name-canonical=true,push=" + push,
		t + ".output=type=oci,dest=" + pushedTar,
		t + ".attest=type=provenance,mode=max",
	}
}

// releaseBakeEnv is the exact job env of a bake job, BAKE_SET aside.
var releaseBakeEnv = map[string]string{
	"BAKE_TARGET": "${{ matrix.image }}",
	"PLATFORM":    "linux/${{ matrix.arch }}",
	"VERSION":     versionExpr,
}

// releaseMatrix is the matrix of the bake jobs: every own image on both
// architectures (the bundle job checks the set against bake's default
// group).
var releaseArchs = []any{"amd64", "arm64"}

// releaseJobKeys are the job keys rule 7 allows; the ones it checks are
// below, the others cannot widen what a job runs.
var releaseJobKeys = map[string]bool{
	"name": true, "runs-on": true, "permissions": true, "needs": true, "if": true,
	"strategy": true, "env": true, "timeout-minutes": true, "steps": true, "outputs": true,
}

// releaseDeniedJobKeys get their own message (P2, P7).
var releaseDeniedJobKeys = map[string]string{
	"uses":              "a job of release.yml calls no reusable workflow",
	"container":         "a job of release.yml runs in no container",
	"services":          "a job of release.yml has no services",
	"concurrency":       "only the workflow-level concurrency group release serialises the runs (B6)",
	"defaults":          "only the workflow's defaults (run.shell: bash) apply",
	"continue-on-error": "a failed job must stop the release",
}

// releaseStepKeys are the step keys of the exact jobs: the spec fixes
// uses, with, run, env and id; no if, shell, working-directory or
// continue-on-error.
var releaseStepKeys = map[string]bool{"name": true, "uses": true, "with": true, "run": true, "env": true, "id": true, "timeout-minutes": true}

// releaseJobEnv are the step env keys of release, attest and
// attest-assets (design-system's RELEASE_JOB_ENV, with this repository's
// names).
var releaseJobEnv = map[string]bool{"GH_TOKEN": true, "TAG": true, "VERSION": true, "BASE": true}

// Repository code in a run text (design-system's CODE_COMMAND, CODE_PATH
// and RELATIVE_COMMAND, without lookbehind and with this repository's
// tools and directories).
var (
	codeCommand     = regexp.MustCompile(`(?:^|[^\w./-])(node|nodejs|npm|npx|pnpm|yarn|corepack|python[\d.]*|pip[\d.]*|pipx|ruby|perl|deno|bun|go|make|gmake)(?:$|[^\w-])`)
	codePath        = regexp.MustCompile(`(?:^|[^\w-])((?:scripts|tools|cmd|internal|images|deploy|node_modules)/)`)
	relativeCommand = regexp.MustCompile("(?:^|[;&|(`{]|\\$\\()\\s*\\.{1,2}/")
	pinnedUses      = regexp.MustCompile(`^([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@[0-9a-f]{40}$`)
)

// checkReleaseWorkflow applies rule 7 to release.yml's single document.
func checkReleaseWorkflow(top *yaml.Node, add func(int, string, ...any)) {
	var wf map[string]any
	if err := top.Decode(&wf); err != nil {
		add(top.Line, "release.yml does not decode: %v", err)
		return
	}
	keyLine := func(k string) int {
		if _, kn := mappingValue(top, k); kn != nil {
			return kn.Line
		}
		return top.Line
	}
	for _, k := range sortedKeys(wf) {
		switch k {
		case "name", "run-name", "on", "permissions", "concurrency", "defaults", "jobs":
		case "env":
			add(keyLine(k), "release.yml has no workflow env: it would reach every job, the ones with write tokens included (P7)")
		default:
			add(keyLine(k), "release.yml: workflow key %s is not in the release policy", k)
		}
	}
	checkReleaseOn(keyLine("on"), wf["on"], add)
	if p, ok := wf["permissions"]; !ok || !reflect.DeepEqual(p, map[string]any{}) {
		add(keyLine("permissions"), "release.yml: the top-level permissions must be exactly {}, so every job names its own (P2), got %v", p)
	}
	if c := wf["concurrency"]; !reflect.DeepEqual(c, map[string]any{"group": "release", "cancel-in-progress": false}) {
		add(keyLine("concurrency"), "release.yml: the workflow-level concurrency must be exactly {group: release, cancel-in-progress: false}: forward-only `latest` needs the runs serialised (P8, B6), got %v", c)
	}
	if d, ok := wf["defaults"]; !ok || !reflect.DeepEqual(d, map[string]any{"run": map[string]any{"shell": "bash"}}) {
		add(keyLine("defaults"), "release.yml: defaults must be exactly run.shell: bash (P7), got %v", d)
	}
	checkVersionEnv(keyLine("env"), "workflow", wf["env"], add)

	jobsNode, jobsKey := mappingValue(top, "jobs")
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		add(top.Line, "release.yml has no jobs mapping")
		return
	}
	seen := map[string]bool{}
	var buildJob map[string]any
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		name, val := jobsNode.Content[i], jobsNode.Content[i+1]
		var job map[string]any
		if err := val.Decode(&job); err != nil {
			add(name.Line, "job %s does not decode: %v", name.Value, err)
			continue
		}
		seen[name.Value] = true
		policy, ok := releaseJobs[name.Value]
		if !ok {
			add(name.Line, "job %s is not in the release policy (jobs: %s)", name.Value, strings.Join(releaseJobOrder, ", "))
			continue
		}
		if name.Value == "build" {
			buildJob = job
		}
		checkReleaseJob(name.Line, name.Value, policy, job, add)
	}
	for _, n := range releaseJobOrder {
		if !seen[n] {
			add(jobsKey.Line, "job %s of the release policy is missing", n)
		}
	}
	// push and push-rehearsal run the build job's matrix (P9).
	if buildJob != nil {
		for i := 0; i+1 < len(jobsNode.Content); i += 2 {
			name := jobsNode.Content[i]
			if name.Value != "push" && name.Value != "push-rehearsal" {
				continue
			}
			var job map[string]any
			if jobsNode.Content[i+1].Decode(&job) == nil && !reflect.DeepEqual(job["strategy"], buildJob["strategy"]) {
				add(name.Line, "job %s: strategy must equal the build job's, so every tested row is pushed (got %v, build has %v)", name.Value, job["strategy"], buildJob["strategy"])
			}
		}
	}
}

// checkReleaseOn checks P8's trigger: workflow_dispatch only, with the
// two inputs.
func checkReleaseOn(line int, on any, add func(int, string, ...any)) {
	m, ok := asMap(on)
	if !ok || len(m) != 1 {
		add(line, "release.yml: on: must be exactly workflow_dispatch (no push, schedule, workflow_call or workflow_run; P8), got %v", on)
		return
	}
	wd, ok := m["workflow_dispatch"]
	if !ok {
		add(line, "release.yml: on: must be exactly workflow_dispatch (P8), got %v", on)
		return
	}
	d, _ := asMap(wd)
	inputs, _ := asMap(d["inputs"])
	if len(d) != 1 || len(inputs) != 2 {
		add(line, "release.yml: workflow_dispatch must have exactly the inputs dry_run and version (P8), got %v", wd)
		return
	}
	check := func(name, typ string, def any) {
		in, ok := asMap(inputs[name])
		if !ok || in["type"] != typ || !reflect.DeepEqual(in["default"], def) {
			add(line, "release.yml: input %s must be type %s with default %#v (P8), got %v", name, typ, def, inputs[name])
			return
		}
		for _, k := range sortedKeys(in) {
			switch {
			case k == "type" || k == "default":
			case k == "description":
				if _, ok := in[k].(string); !ok {
					add(line, "release.yml: input %s: description is not a string", name)
				}
			case k == "required" && in[k] == false:
			default:
				add(line, "release.yml: input %s: key %s is not in the release policy", name, k)
			}
		}
	}
	check("dry_run", "boolean", true)
	check("version", "string", "")
}

// checkVersionEnv reports a VERSION env (any level) that is not exactly
// the version job's output (P8).
func checkVersionEnv(line int, where string, env any, add func(int, string, ...any)) {
	m, _ := asMap(env)
	if v, ok := m["VERSION"]; ok && v != versionExpr {
		add(line, "release.yml: %s env VERSION must be exactly %s (P8), got %v", where, versionExpr, v)
	}
}

// checkReleaseJob checks one job against its policy.
func checkReleaseJob(line int, name string, p releaseJob, job map[string]any, add func(int, string, ...any)) {
	for _, k := range sortedKeys(job) {
		if msg, ok := releaseDeniedJobKeys[k]; ok {
			add(line, "job %s: %s is not allowed: %s", name, k, msg)
		} else if !releaseJobKeys[k] {
			add(line, "job %s: key %s is not in the release policy", name, k)
		}
	}
	want := map[string]any{}
	for k, v := range p.perms {
		want[k] = v
	}
	if !reflect.DeepEqual(job["permissions"], want) {
		add(line, "job %s: permissions must be exactly %v (P2), got %v", name, p.perms, job["permissions"])
	}
	if got := needsList(job["needs"]); !slices.Equal(got, sortedCopy(p.needs)) {
		add(line, "job %s: needs must be exactly %v, so a failed or skipped earlier job stops it (P6), got %v", name, p.needs, job["needs"])
	}
	cond, _ := job["if"].(string)
	if _, has := job["if"]; strings.TrimSpace(cond) != p.cond || (p.cond == "" && has) {
		want := p.cond
		if want == "" {
			want = "(none)"
		}
		add(line, "job %s: if must be exactly %s (P6), got %v", name, want, job["if"])
	}
	switch {
	case p.bake:
		checkReleaseBakeEnv(line, name, job["env"], add)
	case job["env"] != nil:
		add(line, "job %s: env is not allowed: only build, push and push-rehearsal have a job env (P7)", name)
	}
	if p.steps != nil {
		wantRunsOn := plainRunsOn
		if p.bake {
			wantRunsOn = matrixRunsOn
		}
		if job["runs-on"] != wantRunsOn {
			add(line, "job %s: runs-on must be exactly %s (a GitHub-hosted runner for a job with the push path), got %v", name, wantRunsOn, job["runs-on"])
		}
		if !p.bake && job["strategy"] != nil {
			add(line, "job %s: strategy is not allowed", name)
		}
		if !reflect.DeepEqual(job["outputs"], nilIfEmpty(p.outputs)) {
			add(line, "job %s: outputs must be exactly %v, got %v", name, p.outputs, job["outputs"])
		}
	}
	if name == "build" {
		checkReleaseMatrix(line, job["strategy"], add)
	}
	steps, ok := job["steps"].([]any)
	if !ok {
		add(line, "job %s has no steps list", name)
		return
	}
	checkReleaseSteps(line, name, p, steps, add)
}

// checkReleaseMatrix requires both architectures in the build job's
// matrix; push and push-rehearsal must have the same strategy.
func checkReleaseMatrix(line int, strategy any, add func(int, string, ...any)) {
	s, _ := asMap(strategy)
	m, _ := asMap(s["matrix"])
	images, _ := m["image"].([]any)
	if len(m) != 2 || !reflect.DeepEqual(m["arch"], releaseArchs) || len(images) == 0 || s["fail-fast"] != false {
		add(line, "job build: strategy must be fail-fast: false with exactly the matrix image (the own images) and arch [amd64, arm64], got %v", strategy)
	}
}

func nilIfEmpty(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	return m
}

func needsList(v any) []string {
	var out []string
	switch n := v.(type) {
	case string:
		out = []string{n}
	case []any:
		for _, e := range n {
			s, _ := e.(string)
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

// checkReleaseBakeEnv checks a bake job's env: exactly BAKE_TARGET,
// PLATFORM, VERSION and BAKE_SET, with exactly the policy's lines.
func checkReleaseBakeEnv(line int, name string, v any, add func(int, string, ...any)) {
	env, _ := asMap(v)
	for _, k := range sortedKeys(env) {
		if _, ok := releaseBakeEnv[k]; !ok && k != "BAKE_SET" {
			add(line, "job %s: env %s is not in the release policy (BAKE_TARGET, PLATFORM, VERSION, BAKE_SET)", name, k)
		}
	}
	for _, k := range sortedBool(map[string]bool{"BAKE_TARGET": true, "PLATFORM": true, "VERSION": true}) {
		if env[k] != releaseBakeEnv[k] {
			add(line, "job %s: env %s must be exactly %s, got %v", name, k, releaseBakeEnv[k], env[k])
		}
	}
	s, _ := env["BAKE_SET"].(string)
	var got []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			got = append(got, l)
		}
	}
	want := releaseBakeSet(name)
	for _, l := range got {
		if !slices.Contains(want, l) {
			add(line, "job %s: BAKE_SET line %q is not in the release policy (P3; exactly: %s)", name, l, strings.Join(want, " | "))
		}
	}
	for _, l := range want {
		if !slices.Contains(got, l) {
			add(line, "job %s: BAKE_SET lacks the line %q (P3)", name, l)
		}
	}
	if !slices.Equal(got, want) && sameSet(got, want) {
		add(line, "job %s: BAKE_SET lines must be exactly, in this order: %s", name, strings.Join(want, " | "))
	}
}

// sameSet reports whether a and b hold the same lines (in any order or
// number).
func sameSet(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

// checkReleaseSteps checks the steps of a job: everywhere no
// continue-on-error, no ${{ }} in run, VERSION env exact; in the bake
// jobs SOURCE_DATE_EPOCH before the check step; in the exact jobs every
// step as the policy; in release, attest and attest-assets no repository
// code.
func checkReleaseSteps(line int, name string, p releaseJob, steps []any, add func(int, string, ...any)) {
	epochAt, checkAt := -1, -1
	for i, s := range steps {
		step, ok := asMap(s)
		if !ok {
			add(line, "job %s: step %d is not a mapping", name, i+1)
			continue
		}
		if _, ok := step["continue-on-error"]; ok {
			add(line, "job %s: step %d has continue-on-error: a failed step must stop the release (P7)", name, i+1)
		}
		run, _ := step["run"].(string)
		if strings.Contains(run, "${{") {
			add(line, "job %s: step %d has ${{ }} in its run text: inputs, outputs and tokens reach a step only through env (P8)", name, i+1)
		}
		checkVersionEnv(line, fmt.Sprintf("job %s step %d", name, i+1), step["env"], add)
		switch strings.TrimSpace(run) {
		case lineEpoch:
			if epochAt < 0 {
				epochAt = i
			}
		case lineCheck:
			checkAt = i
		}
		if p.noRepoCode {
			checkNoRepoCode(line, name, i, step, add)
		}
		if strings.Contains(strings.ToLower(run), "syft") && (!strings.HasPrefix(strings.TrimSpace(run), syftRun) ||
			!reflect.DeepEqual(asAnyMap(step["env"]), map[string]any{"SYFT_CHECK_FOR_APP_UPDATE": "false"})) {
			add(line, "job %s: step %d runs syft other than as `%s…` with exactly the env SYFT_CHECK_FOR_APP_UPDATE: \"false\" (a literal version through the Go module proxy, no update check; plan revision 2 D.7)", name, i+1, syftRun)
		}
	}
	if p.bake && (epochAt < 0 || checkAt < 0 || epochAt > checkAt) {
		add(line, "job %s: the step `run: %s` is required before the check step: without it a full cache hit still gives another config (B1 M3)", name, lineEpoch)
	}
	if p.steps != nil {
		checkExactSteps(line, name, p.steps, steps, add)
	}
}

// checkNoRepoCode is design-system's checkReleaseJob for one step: no
// checkout, no local action, no shell, step env only from releaseJobEnv,
// and no repository or dependency code in a run text.
func checkNoRepoCode(line int, name string, i int, step map[string]any, add func(int, string, ...any)) {
	where := fmt.Sprintf("job %s: step %d", name, i+1)
	uses, _ := step["uses"].(string)
	if strings.HasPrefix(strings.ToLower(uses), "actions/checkout@") {
		add(line, "%s checks out the repository (%s): this job runs no repository code (P7)", where, uses)
	}
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		add(line, "%s uses the local action %s: this job runs no repository code (P7)", where, uses)
	}
	if _, ok := step["shell"]; ok {
		add(line, "%s sets a shell: only the workflow default bash (P7)", where)
	}
	if _, ok := step["working-directory"]; ok {
		// A working directory is harmless without a checkout, but the
		// download path is fixed; keep the steps plain.
		wd, _ := step["working-directory"].(string)
		if strings.Contains(wd, "${{") {
			add(line, "%s: working-directory has an expression", where)
		}
	}
	env, _ := asMap(step["env"])
	for _, k := range sortedKeys(env) {
		if !releaseJobEnv[k] {
			add(line, "%s: step env %s is not one of %s (P7)", where, k, strings.Join(sortedBool(releaseJobEnv), ", "))
		}
	}
	run, _ := step["run"].(string)
	var code []string
	for _, l := range strings.Split(run, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			code = append(code, l)
		}
	}
	text := strings.Join(code, "\n")
	if m := codeCommand.FindStringSubmatch(text); m != nil {
		add(line, "%s runs repository or dependency code (%s): this job runs no repository code (P7)", where, m[1])
	} else if m := codePath.FindStringSubmatch(text); m != nil {
		add(line, "%s runs repository or dependency code (%s): this job runs no repository code (P7)", where, m[1])
	}
	for _, l := range code {
		if relativeCommand.MatchString(l) {
			add(line, "%s runs a repository-relative command: this job runs no repository code (P7)", where)
			break
		}
	}
}

// checkExactSteps holds a job to its exact steps (P3, P4, P5, P9). Each
// step is checked on its own first (what it runs or uses must be allowed
// in this job at all), then, when the count matches, against the policy's
// step at its position.
func checkExactSteps(line int, name string, want []stepSpec, steps []any, add func(int, string, ...any)) {
	runs := map[string]bool{}
	actions := map[string]bool{}
	for _, s := range want {
		if s.run != "" {
			runs[s.run] = true
		} else {
			actions[s.uses] = true
		}
	}
	ownProblem := make([]bool, len(steps))
	for i, s := range steps {
		step, _ := asMap(s)
		for _, k := range sortedKeys(step) {
			if !releaseStepKeys[k] {
				add(line, "job %s: step %d has %s: a step of this job has no if, shell, working-directory or continue-on-error (P4)", name, i+1, k)
				ownProblem[i] = true
			}
		}
		uses, hasUses := step["uses"].(string)
		run, hasRun := step["run"].(string)
		switch {
		case hasUses && hasRun:
			add(line, "job %s: step %d has both uses and run", name, i+1)
			ownProblem[i] = true
		case hasUses:
			m := pinnedUses.FindStringSubmatch(uses)
			if m == nil || !actions[m[1]] {
				add(line, "job %s: step %d uses %s, which is not one of this job's actions (P9: %s, each pinned to a commit)", name, i+1, uses, strings.Join(sortedBool(actions), ", "))
				ownProblem[i] = true
			}
		case hasRun:
			t := strings.TrimSpace(run)
			if !runs[t] {
				add(line, "job %s: step %d runs a text that is not one of this job's lines; nothing is resolved, the text must equal a line exactly (P4): %q", name, i+1, t)
				ownProblem[i] = true
				for _, msg := range pushJobTextProblems(t) {
					add(line, "job %s: step %d %s", name, i+1, msg)
				}
			}
		default:
			add(line, "job %s: step %d has neither uses nor run", name, i+1)
			ownProblem[i] = true
		}
	}
	if len(steps) != len(want) {
		var list []string
		for _, s := range want {
			if s.run != "" {
				list = append(list, "run: "+s.run)
			} else {
				list = append(list, s.uses)
			}
		}
		add(line, "job %s has %d steps; the release policy has exactly %d, in this order: %s", name, len(steps), len(want), strings.Join(list, " | "))
		return
	}
	for i, s := range steps {
		if ownProblem[i] {
			continue
		}
		step, _ := asMap(s)
		if d := stepDiff(want[i], step); d != "" {
			add(line, "job %s: step %d must be exactly %s: %s", name, i+1, want[i], d)
		}
	}
}

// stepDiff says how a step differs from its spec ("" if it does not).
func stepDiff(want stepSpec, step map[string]any) string {
	id, _ := step["id"].(string)
	if id != want.id {
		return fmt.Sprintf("id %q, want %q", id, want.id)
	}
	if want.uses != "" {
		m := pinnedUses.FindStringSubmatch(fmt.Sprint(step["uses"]))
		if m == nil || m[1] != want.uses {
			return fmt.Sprintf("uses %v", step["uses"])
		}
		if !sameInputs(step["with"], want.with) {
			return fmt.Sprintf("with %v", step["with"])
		}
		if step["env"] != nil {
			return "an action step has no env"
		}
		return ""
	}
	if strings.TrimSpace(fmt.Sprint(step["run"])) != want.run {
		return fmt.Sprintf("run %q", step["run"])
	}
	if step["with"] != nil {
		return "a run step has no with"
	}
	if !reflect.DeepEqual(nilIfEmpty(asAnyMap(step["env"])), nilIfEmpty(want.env)) {
		return fmt.Sprintf("env %v", step["env"])
	}
	return ""
}

func asAnyMap(v any) map[string]any {
	m, _ := asMap(v)
	return m
}

// sameInputs compares action inputs; a string input matches without its
// trailing newline (a `|` block scalar).
func sameInputs(got any, want map[string]any) bool {
	g, ok := asMap(got)
	if !ok || len(g) != len(want) {
		return false
	}
	for k, w := range want {
		v := g[k]
		if ws, ok := w.(string); ok {
			s, ok := v.(string)
			if !ok || strings.TrimRight(s, "\n") != ws {
				return false
			}
			continue
		}
		if !reflect.DeepEqual(v, w) {
			return false
		}
	}
	return true
}

// pushJobTextProblems names, for a run text of a job with the push path
// that is not one of its lines, the forms P3 and P5 forbid: a shell
// function, eval, sh -c, source and xargs, and every other way to push
// or reach a registry or API.
func pushJobTextProblems(text string) []string {
	var out []string
	if shellFunction.MatchString(text) {
		out = append(out, "defines a shell function: a job with packages: write defines no shell function (P5)")
	}
	seen := map[string]bool{}
	for _, words := range shellCommands(text) {
		words = dropRedirects(words)
		i := commandStart(words)
		if i >= len(words) {
			continue
		}
		w := path0(words[i])
		form := ""
		switch {
		case w == "eval" || w == "source" || w == "." || w == "xargs":
			form = w
		case interpreters[w].shell:
			for _, a := range words[i+1:] {
				if a == "-c" || (len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.HasSuffix(a, "c")) {
					form = w + " -c"
				}
			}
		}
		if form != "" && !seen[form] {
			seen[form] = true
			out = append(out, fmt.Sprintf("runs %s: a job with packages: write runs no eval, sh -c, source or xargs (P5)", form))
		}
	}
	uses := imageUses(text)
	for _, words := range commands(text) {
		for _, w := range words {
			switch path0(w) {
			case "oras", "regctl", "curl", "wget":
				uses = append(uses, path0(w))
			case "gh":
				uses = append(uses, "gh")
			}
		}
	}
	for _, u := range uses {
		if !seen[u] {
			seen[u] = true
			out = append(out, fmt.Sprintf("runs %s: an image leaves a job with packages: write only through the checked bake step, -publish-index and -move-latest (P3)", u))
		}
	}
	return out
}

func path0(w string) string {
	return w[strings.LastIndex(w, "/")+1:]
}

// pushJobScripts are the repository scripts a job with packages: write
// may run: none (6836353945's allowlist is empty, plan revision 2 P4).
// checkPushJobScript is what an entry would have to pass.
var pushJobScripts = map[string]bool{}

// checkPushJobScript checks a script on pushJobScripts (P5): no function
// that runs its positional parameters (forwardingFunctions, by name), and
// no eval, sh -c, source or xargs.
func checkPushJobScript(src []byte) []string {
	text := string(src)
	top, funcs := splitFunctions(text)
	var out []string
	fwd := forwardingFunctions(funcs, literalCommands(text), nil)
	for _, n := range sortedBool(fwd) {
		out = append(out, fmt.Sprintf("function %s runs its arguments as a command: a script a job with packages: write runs has no forwarding function (P5)", n))
	}
	for _, f := range append([]string{top}, funcBodies(funcs)...) {
		for _, msg := range pushJobTextProblems(f) {
			if strings.Contains(msg, "(P5)") && !strings.Contains(msg, "shell function") && !slices.Contains(out, msg) {
				out = append(out, msg)
			}
		}
	}
	return out
}

func funcBodies(funcs []shellFunc) []string {
	var out []string
	for _, f := range funcs {
		out = append(out, f.body)
	}
	return out
}
