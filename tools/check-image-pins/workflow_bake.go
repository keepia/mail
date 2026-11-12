package main

import (
	"regexp"
	"sort"
	"strings"
)

// The workflow side of rule 5 (#43 round 3): a workflow builds with bake
// only through docker/bake-action, and only with inputs the check sees.
//
//   - with: only the keys in bakeActionKeys; source is "."; targets is
//     ${{ env.BAKE_TARGET }} and set, if present, ${{ env.BAKE_SET }}, so
//     the build and the check read one definition of both;
//   - no step env on the build step; the job's and workflow's env keys
//     come only from bakeEnvKeys (no BUILDX_*);
//   - every BAKE_SET line sets only an attribute in bakeSetAttrs;
//   - the step right before is `make image-pins-build`, without env, if
//     or continue-on-error: it resolves exactly this build (same targets,
//     set and environment) and checks it;
//   - no run step calls `buildx bake` itself.

const (
	bakeTargetExpr = "${{ env.BAKE_TARGET }}"
	bakeSetExpr    = "${{ env.BAKE_SET }}"
	bakeCheckRun   = "make image-pins-build"
)

// bakeActionKeys are the docker/bake-action inputs a step may use. Not
// allowed, among others: files, workdir, vars (they change the
// definition) and github-token (remote definitions only).
var bakeActionKeys = map[string]bool{
	"source": true, "targets": true, "set": true, "load": true, "push": true,
	"provenance": true, "sbom": true, "no-cache": true, "pull": true,
}

// bakeEnvKeys are the env keys a job that builds with bake may set:
// the shared target and set lines, and PLATFORM (a bake variable that
// only sets platforms; the repository-mode sentinel run shows it steers
// no checked field).
var bakeEnvKeys = map[string]bool{"BAKE_TARGET": true, "BAKE_SET": true, "PLATFORM": true}

// bakeSetAttrs are the target attributes a workflow may --set: the
// layer cache, which does not change what is built from which sources.
var bakeSetAttrs = map[string]bool{"cache-from": true, "cache-to": true}

var ghExpr = regexp.MustCompile(`\$\{\{.*?\}\}`)

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

// checkBakeSteps applies the workflow side of rule 5 to one job.
func checkBakeSteps(line int, job string, wfEnv any, j map[string]any, add func(int, string, ...any)) {
	steps, _ := j["steps"].([]any)
	builds := false
	for i, s := range steps {
		step, ok := asMap(s)
		if !ok {
			continue
		}
		if run, ok := step["run"].(string); ok && strings.Contains(strings.Join(strings.Fields(run), " "), "buildx bake") {
			add(line, "job %s: step %d runs `buildx bake` itself; build with docker/bake-action (rule 5)", job, i+1)
		}
		uses, _ := step["uses"].(string)
		if !strings.HasPrefix(uses, "docker/bake-action@") {
			continue
		}
		builds = true
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
			add(line, "job %s: docker/bake-action targets must be %s (got %v), shared with %q", job, bakeTargetExpr, with["targets"], bakeCheckRun)
		}
		if set, ok := with["set"]; ok && set != bakeSetExpr {
			add(line, "job %s: docker/bake-action set must be %s (got %q), shared with %q", job, bakeSetExpr, set, bakeCheckRun)
		}
		if _, ok := step["env"]; ok {
			add(line, "job %s: the docker/bake-action step has its own env; set build inputs at job level (%s)", job, strings.Join(sortedBool(bakeEnvKeys), ", "))
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
			add(line, "job %s: the step right before docker/bake-action must be `run: %s`, without env, if or continue-on-error, so the check resolves exactly this build", job, bakeCheckRun)
		}
	}
	if !builds {
		return
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
			}
		}
		if scope.name == "job" {
			checkBakeSetEnv(line, job, env["BAKE_SET"], add)
		}
	}
}

// checkBakeSetEnv checks the BAKE_SET lines of a job.
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
		if attr := setLineAttr(l); !bakeSetAttrs[attr] {
			add(line, "job %s: BAKE_SET line %q sets %q; only %s are allowed", job, l, attr, strings.Join(sortedBool(bakeSetAttrs), ", "))
		}
	}
}

func sortedBool(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
