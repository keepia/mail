package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// CheckWorkflow checks a workflow file.
//
// In every workflow, release.yml included, the images a job runs in are
// pinned: each `jobs.<id>.container` (a string or its `image`) and each
// `jobs.<id>.services.<name>.image` is name:tag@sha256:<64 hex>, and so
// is the BuildKit image of every docker/setup-buildx-action step
// (driver-opts image=; checkBuilderImages). Outside release.yml that step
// has exactly CI's inputs (stepSetupBake.with, #66 D3); release.yml's
// steps are rule 7's. Action references (`uses: docker://…`) are
// tools/check-action-pins' rule.
//
// In every workflow, a job uses only the builder setup-buildx started
// (#66 D2, checkBuilderSwitches): no step text, and in a job that builds
// with bake no text it runs, creates or selects another builder or Docker
// context, and no env sets BUILDX_BUILDER, DOCKER_CONTEXT or DOCKER_HOST.
//
// Rule 6 applies to every workflow except release.yml: nothing grants
// `packages: write`, so only the release workflow can push to GHCR.
// Reported are:
//   - `packages: write` at workflow or job level;
//   - `permissions: write-all` at either level (it includes packages);
//   - a job that calls a reusable workflow (`uses:`) without its own
//     permissions block: it inherits the caller's permissions;
//   - a job without permissions in a workflow without them: it gets the
//     repository's default token permissions, which this check cannot see.
//
// Other permission values are left to review.
//
// The rule-5 side (workflow_bake.go): images are built only by the one
// checked docker/bake-action step per job, and every other build path is
// reported.
//
// It also returns the text of every run step, so the caller can check the
// scripts they run. resolve (nil in single-file fixtures) gives the files
// a step's text names, for the rules on what a step runs.
func CheckWorkflow(src []byte, release bool, resolve resolver) ([]Finding, []string, error) {
	docs, err := parseYAML(src)
	if err != nil {
		return nil, nil, err
	}
	var out []Finding
	var runs []string
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}
	if len(docs) != 1 {
		add(0, "a workflow must hold exactly one YAML document, found %d", len(docs))
		return out, runs, nil
	}
	var wf struct {
		Permissions any `yaml:"permissions"`
		Env         any `yaml:"env"`
		Defaults    any `yaml:"defaults"`
	}
	top := root(docs[0])
	if err := top.Decode(&wf); err != nil {
		add(top.Line, "the workflow does not decode: %v", err)
		return out, runs, nil
	}
	_, topKey := mappingValue(top, "permissions")
	if topKey != nil && !release {
		checkPermissions(topKey.Line, "workflow", wf.Permissions, add)
	}
	if release {
		checkReleaseWorkflow(top, add)
	}
	if _, envKey := mappingValue(top, "env"); envKey != nil {
		checkBuilderEnv(envKey.Line, "workflow env", wf.Env, release, add)
	}
	jobs, _ := mappingValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return out, runs, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, val := jobs.Content[i], jobs.Content[i+1]
		var job map[string]any
		if err := val.Decode(&job); err != nil {
			add(name.Line, "job %s does not decode: %v", name.Value, err)
			continue
		}
		checkJobImages(name.Line, name.Value, job, add)
		checkBuilderImages(name.Line, name.Value, job, release, add)
		checkBuilderSwitches(name.Line, name.Value, wf.Defaults, job, release, resolve, add)
		runs = append(runs, checkJobBuilds(name.Line, name.Value, wf.Env, wf.Defaults, job, release, resolve, add)...)
		if release {
			continue
		}
		perms, hasPerms := job["permissions"]
		if hasPerms {
			checkPermissions(name.Line, "job "+name.Value, perms, add)
		}
		if _, calls := job["uses"]; calls && !hasPerms {
			add(name.Line, "job %s calls a reusable workflow without a permissions block; it would inherit the caller's permissions", name.Value)
		} else if !hasPerms && topKey == nil {
			add(name.Line, "job %s has no permissions and the workflow sets none; it gets the repository default", name.Value)
		}
	}
	return out, runs, nil
}

// checkJobImages checks the container and service images of one job. The
// image may be a string or a mapping with `image`; any other shape, and an
// expression (`${{ … }}`), is reported.
func checkJobImages(line int, job string, j map[string]any, add func(int, string, ...any)) {
	check := func(where string, v any) {
		if m, ok := v.(map[string]any); ok {
			v = m["image"]
		}
		s, ok := v.(string)
		switch {
		case !ok:
			add(line, "job %s: %s has no image string", job, where)
		case !isPinnedImage(s):
			add(line, "job %s: %s", job, unpinnedMsg(where+" image", s))
		}
	}
	if c, ok := j["container"]; ok {
		check("container", c)
	}
	if s, ok := j["services"]; ok {
		services, ok := s.(map[string]any)
		if !ok {
			add(line, "job %s: services is not a mapping", job)
			return
		}
		names := make([]string, 0, len(services))
		for n := range services {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			check("service "+n, services[n])
		}
	}
}

// checkBuilderImages checks the BuildKit image of every builder a job
// starts with docker/setup-buildx-action (#71 review B, N6): the
// docker-container driver (the action's default, the only one the bake
// steps' type=gha cache works with) runs BuildKit from driver-opts'
// image=, or from the floating moby/buildkit:buildx-stable-1 when none is
// given. The push bake step hands that container the GHCR credentials,
// so the image is pinned like every other: exactly one image= entry,
// name:tag@sha256:<64 hex>, and no input but driver-opts,
// buildkitd-config-inline and driver (docker-container only).
//
// Outside release.yml (release false) the inputs are also exactly CI's,
// stepSetupBake.with (#66 D3): no other driver-opts entry (network=host
// is push-rehearsal's alone), no other buildkitd-config-inline, and no
// explicit driver. release.yml's steps are held exactly by rule 7
// (checkReleaseSteps, checkExactSteps), push-rehearsal's host-network
// builder included.
// builderInputs are the docker/setup-buildx-action inputs a workflow may
// set.
var builderInputs = map[string]bool{"driver-opts": true, "buildkitd-config-inline": true, "driver": true}

func checkBuilderImages(line int, job string, j map[string]any, release bool, add func(int, string, ...any)) {
	steps, _ := j["steps"].([]any)
	for i, s := range steps {
		step, _ := asMap(s)
		uses, _ := step["uses"].(string)
		if a, _, _ := strings.Cut(strings.ToLower(uses), "@"); a != "docker/setup-buildx-action" {
			continue
		}
		with, _ := asMap(step["with"])
		// Only these inputs (#72 review B, N2): append adds nodes with
		// their own image, endpoint a remote builder, version an unpinned
		// buildx download.
		for _, k := range sortedKeys(with) {
			if !builderInputs[k] {
				add(line, "job %s: step %d: docker/setup-buildx-action input %s is not allowed: only driver-opts, buildkitd-config-inline and driver: docker-container", job, i+1, k)
			}
		}
		if !release && !sameInputs(step["with"], stepSetupBake.with) {
			add(line, "job %s: step %d: docker/setup-buildx-action outside release.yml has exactly CI's inputs %#v (#66 D3), got %#v", job, i+1, stepSetupBake.with, step["with"])
		}
		if d, ok := with["driver"]; ok && d != "docker-container" {
			add(line, "job %s: step %d: docker/setup-buildx-action with driver %v: only the docker-container driver, with a pinned BuildKit image", job, i+1, d)
			continue
		}
		opts, _ := with["driver-opts"].(string)
		var images []string
		for _, l := range strings.Split(opts, "\n") {
			for _, f := range strings.Split(l, ",") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(f), "image="); ok {
					images = append(images, v)
				}
			}
		}
		switch {
		case len(images) == 0:
			add(line, "job %s: step %d: docker/setup-buildx-action starts BuildKit from the floating moby/buildkit:buildx-stable-1; name it in driver-opts as image=name:tag@sha256:<64 hex>", job, i+1)
		case len(images) > 1:
			add(line, "job %s: step %d: docker/setup-buildx-action names %d BuildKit images in driver-opts, want one", job, i+1, len(images))
		case !isPinnedImage(images[0]):
			add(line, "job %s: step %d: %s", job, i+1, unpinnedMsg("BuildKit image (driver-opts)", images[0]))
		}
	}
}

// builderEnvKeys are the env keys that point every later docker and
// buildx command at another builder, Docker context or daemon (#66 D2;
// DOCKER_HOST is of DOCKER_CONTEXT's kind, CD6).
var builderEnvKeys = []string{"BUILDX_BUILDER", "DOCKER_CONTEXT", "DOCKER_HOST"}

// checkBuilderEnv reports each of builderEnvKeys that an env sets; where
// names the env (workflow env, a job's env, a step's env). Outside
// release.yml an env that is not a literal mapping (an expression such as
// `env: ${{ fromJSON(…) }}`) is reported too, because it could set them
// unseen; in release.yml rule 7 reports every such env.
func checkBuilderEnv(line int, where string, env any, release bool, add func(int, string, ...any)) {
	if env == nil {
		return
	}
	m, ok := asMap(env)
	if !ok {
		if !release {
			add(line, "%s is not a mapping (%v): the check cannot see whether it sets %s (#66 D2)", where, env, strings.Join(builderEnvKeys, ", "))
		}
		return
	}
	for _, k := range builderEnvKeys {
		if _, ok := m[k]; ok {
			add(line, "%s sets %s: docker and buildx would use another builder, context or daemon than the one docker/setup-buildx-action started (#66 D2)", where, k)
		}
	}
}

// checkBuilderSwitches applies #66 D2 to one job. A job builds with the
// builder docker/setup-buildx-action started, with the pinned BuildKit
// image (in release.yml the one that writes the release cache). So a step
// that creates or selects another builder or Docker context
// (builderSwitches) is reported: in its own run text or github-script in
// every job, and in a job that builds with bake also in every text the
// step runs (a script, a make target, a local action; resolve). So is an
// env of the job or of a step that sets one of builderEnvKeys (the
// workflow env is checked once, in CheckWorkflow).
func checkBuilderSwitches(line int, job string, wfDefaults any, j map[string]any, release bool, resolve resolver, add func(int, string, ...any)) {
	steps, _ := j["steps"].([]any)
	builds := false
	for _, s := range steps {
		step, _ := asMap(s)
		uses, _ := step["uses"].(string)
		if strings.HasPrefix(strings.ToLower(uses), "docker/bake-action@") {
			builds = true
		}
	}
	if !builds {
		resolve = nil
	}
	checkBuilderEnv(line, "job "+job+": job env", j["env"], release, add)
	workdir := defaultWorkdir(wfDefaults, j["defaults"])
	for i, s := range steps {
		step, ok := asMap(s)
		if !ok {
			continue
		}
		checkBuilderEnv(line, fmt.Sprintf("job %s: step %d: env", job, i+1), step["env"], release, add)
		texts, _ := stepTexts(step, workdir, resolve)
		var seen []string
		for _, t := range texts {
			if !t.exec {
				continue
			}
			in := ""
			if t.path != "" {
				in = " in " + t.path
			}
			for _, c := range builderSwitches(t.text) {
				msg := fmt.Sprintf("job %s: step %d runs %s%s: a job uses only the builder docker/setup-buildx-action started; no step creates or selects another builder or Docker context (#66 D2)", job, i+1, c, in)
				if !slices.Contains(seen, msg) {
					seen = append(seen, msg)
					add(line, "%s", msg)
				}
			}
		}
	}
}

// builderSwitches returns the commands in a text that create or select a
// builder or a Docker context (#66 D2): buildx create and use (also as
// docker buildx, the docker-buildx plugin binary, and docker builder,
// buildx's alias), and docker context create, import and use. Global
// options before a subcommand are skipped (subcommand).
func builderSwitches(text string) []string {
	var found []string
	for _, words := range commands(text) {
		for i, w := range words {
			base := path0(w)
			rest := words[i+1:]
			switch {
			case base == "buildx" || base == "docker-buildx":
				if sub, _ := subcommand(rest); sub == "create" || sub == "use" {
					found = append(found, "buildx "+sub)
				}
			case engines[base]:
				sub, after := subcommand(rest)
				sub2, _ := subcommand(after)
				switch {
				case sub == "builder" && (sub2 == "create" || sub2 == "use"):
					found = append(found, base+" builder "+sub2)
				case sub == "context" && (sub2 == "create" || sub2 == "import" || sub2 == "use"):
					found = append(found, base+" context "+sub2)
				}
			}
		}
	}
	return found
}

func checkPermissions(line int, where string, perms any, add func(int, string, ...any)) {
	switch p := perms.(type) {
	case string:
		if p == "write-all" {
			add(line, "%s grants write-all, which includes packages: write; only release.yml may push packages", where)
		}
	case map[string]any:
		if v, ok := p["packages"]; ok && v == "write" {
			add(line, "%s grants packages: write; only release.yml may push packages", where)
		}
	}
}
