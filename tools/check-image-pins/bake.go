package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule 5 checks the bake definition as Docker resolves it, not its HCL
// lines: `docker buildx bake --print` applies inheritance, variables,
// functions and one-line blocks, and prints every target as JSON. The
// check then reads exactly what a build would use. It needs the buildx
// CLI plugin (not a running daemon); without it the check fails closed.

// bakeTarget is the part of a resolved bake target that rule 5 reads.
type bakeTarget struct {
	Context          string             `json:"context"`
	Contexts         map[string]string  `json:"contexts"`
	Dockerfile       string             `json:"dockerfile"`
	DockerfileInline string             `json:"dockerfile-inline"`
	Args             map[string]*string `json:"args"`
}

// bakeDecl finds target names declared in HCL, including hidden ones
// (`target "_common"`), which `bake --list` leaves out. A name found here
// that bake does not know makes --print fail, which is reported.
var bakeDecl = regexp.MustCompile(`\btarget\s+"([^"]+)"`)

// bakeRunner runs `docker buildx bake` with args in dir and returns its
// standard output.
func bakeRunner(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("docker", append([]string{"buildx", "bake", "--progress=quiet"}, args...)...) //nolint:gosec // fixed program; the arguments are target names from the repository's own bake file
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker buildx bake %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// bakeTargetNames lists every target of the bake definition in root: the
// ones `bake --list` shows and every name declared in the HCL sources.
func bakeTargetNames(root string, hcl [][]byte) ([]string, error) {
	names := map[string]bool{}
	out, err := bakeRunner(root, "--list=type=targets,format=json")
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
	for _, t := range listed {
		if !t.Group {
			names[t.Name] = true
		}
	}
	for _, src := range hcl {
		for _, line := range strings.Split(string(src), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
				continue
			}
			for _, m := range bakeDecl.FindAllStringSubmatch(l, -1) {
				names[m[1]] = true
			}
		}
	}
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	return sorted, nil
}

// resolveBake returns every resolved target of the bake definition in
// root.
func resolveBake(root string, hcl [][]byte) (map[string]bakeTarget, error) {
	names, err := bakeTargetNames(root, hcl)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("the bake definition has no targets")
	}
	out, err := bakeRunner(root, append([]string{"--print"}, names...)...)
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
		for k := range t.Args {
			if strings.EqualFold(k, "BUILDKIT_SYNTAX") {
				bad("the BUILDKIT_SYNTAX argument overrides the pinned # syntax= directive")
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
