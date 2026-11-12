// Command check-image-pins checks that every image and download a build
// uses is pinned, and that only the release workflow can push packages:
//
//  1. a Dockerfile's `# syntax=` is name:X.Y.Z@sha256:<64 hex>;
//  2. every FROM, COPY --from= and RUN --mount=...,from= names an earlier
//     stage or name:tag@sha256:<64 hex>;
//  3. every ADD from http(s):// has --checksum=sha256:<64 hex>; ADD of a
//     git URL is reported;
//  4. a Compose file's services: image by digest, or a build of an image
//     under ${KEEPIA_REGISTRY...} from a local context;
//  5. a docker-bake*.hcl: every context is a relative path, and there are
//     no named `contexts`;
//  6. no workflow except release.yml grants packages: write.
//
// It fails closed: a form it cannot read is reported, not skipped. The
// rules are in dockerfile.go, compose.go, bake.go and workflow.go and in
// docs/development/index.md ("Images").
//
// Usage: check-image-pins [root]  (default: the current directory, which
// `make image-pins` sets to the repository root). It walks root and skips
// .git, bin, prototypes (throwaway prototypes, never built by CI or
// released) and every testdata directory. Exits 1 on a finding, 2 on a
// usage error.
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

// skipDirs are directory names the walk does not enter.
var skipDirs = map[string]bool{".git": true, "bin": true, "prototypes": true, "testdata": true, "node_modules": true}

// kind is what a file is checked as.
type kind int

const (
	kindNone kind = iota
	kindDockerfile
	kindCompose
	kindBake
	kindBakeJSON
	kindWorkflow
)

// classify returns how the file at rel (slash-separated, relative to the
// root) is checked.
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
			return kindNone
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

// checkFile runs the rules for k on src.
func checkFile(k kind, src []byte) ([]Finding, error) {
	switch k {
	case kindDockerfile:
		return CheckDockerfile(src), nil
	case kindCompose:
		return CheckCompose(src)
	case kindBake:
		return CheckBake(src), nil
	case kindBakeJSON:
		return []Finding{{0, "a JSON bake file is not read by this check; use docker-bake.hcl"}}, nil
	case kindWorkflow:
		return CheckWorkflow(src)
	}
	return nil, nil
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

	type file struct {
		path string
		kind kind
	}
	var files []file
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { //nolint:gosec // root is the tool's own argument: the tree to check; CI runs it with contents: read
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if k := classify(rel); k != kindNone {
			files = append(files, file{p, k})
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "check-image-pins: %v\n", err)
		return 2
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	bad := 0
	counts := map[kind]int{}
	for _, f := range files {
		counts[f.kind]++
		src, err := os.ReadFile(f.path) //nolint:gosec // f.path is a file found by walking root, the tree the tool is told to check
		if err != nil {
			fmt.Fprintf(stdout, "%s: %v\n", f.path, err)
			bad++
			continue
		}
		findings, err := checkFile(f.kind, src)
		if err != nil {
			fmt.Fprintf(stdout, "%s: does not parse: %v\n", f.path, err)
			bad++
			continue
		}
		for _, fd := range findings {
			fmt.Fprintf(stdout, "%s:%s\n", f.path, fd)
			bad++
		}
	}
	if counts[kindDockerfile] == 0 {
		fmt.Fprintf(stderr, "check-image-pins: no Dockerfile under %s\n", root)
		return 2
	}
	if bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s) in %d file(s) checked.\n", bad, len(files))
		return 1
	}
	fmt.Fprintf(stdout, "check-image-pins: every image and download is pinned (%d Dockerfiles, %d Compose files, %d bake files, %d workflows).\n",
		counts[kindDockerfile], counts[kindCompose], counts[kindBake], counts[kindWorkflow])
	return 0
}
