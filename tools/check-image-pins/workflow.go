package main

import (
	"fmt"
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
// (driver-opts image=; checkBuilderImages). Action references (`uses:
// docker://…`) are tools/check-action-pins' rule.
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
		checkBuilderImages(name.Line, name.Value, job, add)
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
// name:tag@sha256:<64 hex>.
func checkBuilderImages(line int, job string, j map[string]any, add func(int, string, ...any)) {
	steps, _ := j["steps"].([]any)
	for i, s := range steps {
		step, _ := asMap(s)
		uses, _ := step["uses"].(string)
		if a, _, _ := strings.Cut(strings.ToLower(uses), "@"); a != "docker/setup-buildx-action" {
			continue
		}
		with, _ := asMap(step["with"])
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
