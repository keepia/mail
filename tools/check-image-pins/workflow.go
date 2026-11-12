package main

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// CheckWorkflow applies rule 6 of the image pin check to a workflow other
// than release.yml: nothing grants `packages: write`, so only the release
// workflow can push to GHCR. Reported are:
//   - `packages: write` at workflow or job level;
//   - `permissions: write-all` at either level (it includes packages);
//   - a job that calls a reusable workflow (`uses:`) without its own
//     permissions block: it inherits the caller's permissions;
//   - a job without permissions in a workflow without them: it gets the
//     repository's default token permissions, which this check cannot see.
//
// Other permission values are left to review.
func CheckWorkflow(src []byte) ([]Finding, error) {
	docs, err := parseYAML(src)
	if err != nil {
		return nil, err
	}
	var out []Finding
	add := func(line int, format string, a ...any) {
		out = append(out, Finding{line, fmt.Sprintf(format, a...)})
	}
	if len(docs) != 1 {
		add(0, "a workflow must hold exactly one YAML document, found %d", len(docs))
		return out, nil
	}
	var wf struct {
		Permissions any `yaml:"permissions"`
	}
	top := root(docs[0])
	if err := top.Decode(&wf); err != nil {
		add(top.Line, "the workflow does not decode: %v", err)
		return out, nil
	}
	_, topKey := mappingValue(top, "permissions")
	if topKey != nil {
		checkPermissions(topKey.Line, "workflow", wf.Permissions, add)
	}
	jobs, _ := mappingValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return out, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, val := jobs.Content[i], jobs.Content[i+1]
		var job map[string]any
		if err := val.Decode(&job); err != nil {
			add(name.Line, "job %s does not decode: %v", name.Value, err)
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
	return out, nil
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
