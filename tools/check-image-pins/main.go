// Command check-image-pins checks that every image and download a build
// uses is pinned, and that only the release workflow can push packages:
//
//  1. a Dockerfile's `# syntax=` is name:X.Y.Z@sha256:<64 hex>;
//  2. every FROM, COPY --from= and RUN --mount=...,from= names an earlier
//     stage or name:tag@sha256:<64 hex>;
//  3. every ADD from http(s):// has --checksum=sha256:<64 hex>; ADD of a
//     git URL, and an ADD source with a variable, are reported;
//  4. a Compose file's services: image by digest, or a build of an image
//     under ${KEEPIA_REGISTRY...} from a local context;
//  5. the bake definition, as `docker buildx bake --print` resolves it:
//     every context is a relative path, and there are no named contexts,
//     no dockerfile-inline and no BUILDKIT_SYNTAX argument;
//  6. no workflow except release.yml grants packages: write; in every
//     workflow, job container and service images are pinned by digest.
//
// Every Dockerfile a bake target or a Compose build names is checked with
// rules 1-3, whatever its name and wherever it lives, so the walk's
// skipped directories cannot hide one.
//
// It fails closed: a form it cannot read is reported, not skipped. Rule 5
// needs the docker CLI with buildx (no daemon); without it the check
// reports the bake file and fails. The rules are in dockerfile.go,
// compose.go, bake.go and workflow.go and in docs/development/index.md
// ("Images").
//
// Usage: check-image-pins [root]  (default: the current directory, which
// `make image-pins` sets to the repository root). It walks root and skips
// only the paths in skipPaths. Exits 1 on a finding, 2 on a usage error.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// skipPaths are the directories the walk does not enter, relative to the
// root: git's own data, built tools, the throwaway prototypes (never built
// by CI or released, C10), and the fixtures of the repository's checks,
// which are unpinned on purpose. A directory of the same name elsewhere is
// walked, and a Dockerfile that bake or Compose names inside a skipped
// path is still checked.
var skipPaths = map[string]bool{
	".git":                             true,
	"bin":                              true,
	"prototypes":                       true,
	"scripts/testdata":                 true,
	"tools/check-action-pins/testdata": true,
	"tools/check-image-pins/testdata":  true,
}

// kind is what a file is checked as.
type kind int

const (
	kindNone kind = iota
	kindDockerfile
	kindCompose
	kindBake
	kindBakeJSON
	kindWorkflow
	kindReleaseWorkflow
)

// classify returns how the file at rel (relative to the root) is checked.
func classify(rel string) kind {
	base := filepath.Base(rel)
	lower := strings.ToLower(base)
	dir := filepath.ToSlash(filepath.Dir(rel))
	switch {
	case strings.HasSuffix(lower, ".go"):
		// Go sources such as this tool's dockerfile.go.
		return kindNone
	case dir == ".github/workflows" && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		if lower == "release.yml" || lower == "release.yaml" {
			return kindReleaseWorkflow
		}
		return kindWorkflow
	case lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile"):
		return kindDockerfile
	case (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose")) &&
		(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return kindCompose
	case strings.HasPrefix(lower, "docker-bake") && strings.HasSuffix(lower, ".hcl"):
		return kindBake
	case strings.HasPrefix(lower, "docker-bake") && strings.HasSuffix(lower, ".json"):
		return kindBakeJSON
	}
	return kindNone
}

// report collects findings per file and prints them.
type report struct {
	out io.Writer
	bad int
}

// add prints one finding on one line (a multi-line message, such as
// docker's error output, is joined with " | ").
func (r *report) add(path string, line int, msg string) {
	msg = strings.Join(strings.Fields(strings.ReplaceAll(msg, "\n", " | ")), " ")
	fmt.Fprintf(r.out, "%s:%d: %s\n", path, line, msg)
	r.bad++
}

func (r *report) addAll(path string, findings []Finding) {
	for _, f := range findings {
		r.add(path, f.Line, f.Msg)
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	root := "."
	switch len(args) {
	case 0:
	case 1:
		root = args[0]
	default:
		fmt.Fprintln(stderr, "usage: check-image-pins [root]")
		return 2
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() { //nolint:gosec // root is the tool's own argument: the tree to check
		fmt.Fprintf(stderr, "check-image-pins: no directory %s\n", root)
		return 2
	}

	files := map[kind][]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { //nolint:gosec // root is the tool's own argument: the tree to check; CI runs it with contents: read
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipPaths[filepath.ToSlash(rel)] {
				return filepath.SkipDir
			}
			return nil
		}
		if k := classify(rel); k != kindNone {
			files[k] = append(files[k], p)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "check-image-pins: %v\n", err)
		return 2
	}

	r := &report{out: stdout}
	// Dockerfiles to check: the ones the walk found, plus every one that a
	// bake target or a Compose build names (deduplicated by path).
	dockerfiles := map[string]bool{}
	for _, p := range files[kindDockerfile] {
		dockerfiles[filepath.Clean(p)] = true
	}
	inRoot := func(from, p string) bool {
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			r.add(from, 0, fmt.Sprintf("names a Dockerfile outside the repository: %s", p))
			return false
		}
		return true
	}

	for _, p := range files[kindCompose] {
		src, err := os.ReadFile(p) //nolint:gosec // p is a file found by walking root
		if err != nil {
			r.add(p, 0, err.Error())
			continue
		}
		findings, refs, err := CheckCompose(src)
		if err != nil {
			r.add(p, 0, "does not parse: "+err.Error())
			continue
		}
		r.addAll(p, findings)
		for _, ref := range refs {
			df := filepath.Join(filepath.Dir(p), filepath.FromSlash(ref))
			if inRoot(p, df) {
				dockerfiles[filepath.Clean(df)] = true
			}
		}
	}

	var rootBake []string
	var hcl [][]byte
	for _, p := range files[kindBake] {
		if filepath.Dir(p) != filepath.Clean(root) {
			r.add(p, 0, "a bake file outside the repository root is not resolved by this check; keep the bake definition at the root")
			continue
		}
		src, err := os.ReadFile(p) //nolint:gosec // p is a file found by walking root
		if err != nil {
			r.add(p, 0, err.Error())
			continue
		}
		rootBake = append(rootBake, p)
		hcl = append(hcl, src)
	}
	for _, p := range files[kindBakeJSON] {
		r.add(p, 0, "a JSON bake file is not read by this check; use docker-bake.hcl")
	}
	if len(rootBake) > 0 {
		label := strings.Join(rootBake, ",")
		targets, err := resolveBake(root, hcl)
		if err != nil {
			r.add(label, 0, "cannot resolve the bake definition (rule 5 needs the docker CLI with buildx): "+err.Error())
		} else {
			findings, refs := CheckBakeTargets(root, targets)
			for _, f := range findings {
				r.add(label, 0, f)
			}
			for _, df := range refs {
				if inRoot(label, df) {
					dockerfiles[filepath.Clean(df)] = true
				}
			}
		}
	}

	var dfs []string
	for p := range dockerfiles {
		dfs = append(dfs, p)
	}
	sort.Strings(dfs)
	for _, p := range dfs {
		src, err := os.ReadFile(p) //nolint:gosec // p was found by the walk or named by the repository's own bake or Compose file, inside root
		if err != nil {
			r.add(p, 0, err.Error())
			continue
		}
		r.addAll(p, CheckDockerfile(src))
	}

	for _, k := range []kind{kindWorkflow, kindReleaseWorkflow} {
		for _, p := range files[k] {
			src, err := os.ReadFile(p) //nolint:gosec // p is a file found by walking root
			if err != nil {
				r.add(p, 0, err.Error())
				continue
			}
			findings, err := CheckWorkflow(src, k == kindReleaseWorkflow)
			if err != nil {
				r.add(p, 0, "does not parse: "+err.Error())
				continue
			}
			r.addAll(p, findings)
		}
	}

	if len(dfs) == 0 {
		fmt.Fprintf(stderr, "check-image-pins: no Dockerfile under %s\n", root)
		return 2
	}
	workflows := len(files[kindWorkflow]) + len(files[kindReleaseWorkflow])
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s); checked %d Dockerfiles, %d Compose files, %d bake files, %d workflows.\n",
			r.bad, len(dfs), len(files[kindCompose]), len(rootBake), workflows)
		return 1
	}
	fmt.Fprintf(stdout, "check-image-pins: every image and download is pinned (%d Dockerfiles, %d Compose files, %d bake files, %d workflows).\n",
		len(dfs), len(files[kindCompose]), len(rootBake), workflows)
	return 0
}
