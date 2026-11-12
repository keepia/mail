// Command check-action-pins checks that every `uses` key in the workflows
// and composite actions of a repository is pinned:
//   - an action or reusable workflow: owner/repo[/path]@<full 40-hex commit
//     SHA> with a `# vX.Y.Z` line comment (Dependabot keeps both current);
//   - a local action (`./path`) as is;
//   - a Docker action: docker://image@sha256:<64 hex>.
//
// It parses the files with a YAML parser; the rules are in check.go and in
// docs/development/index.md.
//
// Usage: check-action-pins [root]  (default: the current directory, which
// `make workflows` sets to the repository root). It checks
// <root>/.github/workflows/*.y*ml, every action.y*ml under
// <root>/.github/actions, and the action.y*ml of every local action
// (`uses: ./path`) found in those files. Exits 1 if anything is not pinned
// or a file does not parse, 2 on a usage error (no workflow files).
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

func run(args []string, stdout, stderr io.Writer) int {
	root := "."
	switch len(args) {
	case 0:
	case 1:
		root = args[0]
	default:
		fmt.Fprintln(stderr, "usage: check-action-pins [root]")
		return 2
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() { //nolint:gosec // root is the tool's own argument: the tree to check; CI runs it with contents: read
		fmt.Fprintf(stderr, "check-action-pins: no directory %s\n", root)
		return 2
	}

	workflows, err := workflowFiles(root)
	if err != nil {
		fmt.Fprintf(stderr, "check-action-pins: %v\n", err)
		return 2
	}
	if len(workflows) == 0 {
		fmt.Fprintf(stderr, "check-action-pins: no workflow files in %s\n", filepath.Join(root, ".github", "workflows"))
		return 2
	}
	actions, err := actionFiles(root)
	if err != nil {
		fmt.Fprintf(stderr, "check-action-pins: %v\n", err)
		return 2
	}

	queue := append(workflows, actions...)
	seen := map[string]bool{}
	for _, f := range queue {
		seen[f] = true
	}
	bad := 0
	for i := 0; i < len(queue); i++ {
		f := queue[i]
		src, err := os.ReadFile(f) //nolint:gosec // f is a workflow or action file under root; local action paths that leave root are dropped (localActionFiles, the ".." check)
		if err != nil {
			fmt.Fprintf(stdout, "%s: %v\n", f, err)
			bad++
			continue
		}
		findings, err := Check(src)
		for _, fd := range findings {
			fmt.Fprintf(stdout, "%s:%s\n", f, fd)
			bad++
		}
		if err != nil {
			fmt.Fprintf(stdout, "%s: does not parse: %v\n", f, err)
			bad++
			continue
		}
		for _, ref := range LocalActions(src) {
			for _, a := range localActionFiles(root, ref) {
				if !seen[a] {
					seen[a] = true
					queue = append(queue, a)
				}
			}
		}
	}

	if bad > 0 {
		fmt.Fprintf(stdout, "check-action-pins: %d finding(s) in %d file(s) checked.\n", bad, len(queue))
		return 1
	}
	fmt.Fprintf(stdout, "check-action-pins: every uses: is pinned (%d files: %d workflows, %d actions).\n",
		len(queue), len(workflows), len(queue)-len(workflows))
	return 0
}

// workflowFiles lists the *.yml and *.yaml files directly in
// <root>/.github/workflows. A missing directory gives none.
func workflowFiles(root string) ([]string, error) {
	var files []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(root, ".github", "workflows", pattern))
		if err != nil {
			return nil, err
		}
		for _, f := range m {
			if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() { //nolint:gosec // f is a glob match under root, the tree the tool is told to check
				files = append(files, f)
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

// actionFiles lists every action.yml and action.yaml under
// <root>/.github/actions, at any depth. A missing directory gives none.
func actionFiles(root string) ([]string, error) {
	dir := filepath.Join(root, ".github", "actions")
	if _, err := os.Stat(dir); os.IsNotExist(err) { //nolint:gosec // dir is <root>/.github/actions, under the tree the tool is told to check
		return nil, nil
	}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error { //nolint:gosec // dir is <root>/.github/actions, under the tree the tool is told to check
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && isActionFile(d.Name()) {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

func isActionFile(name string) bool {
	return name == "action.yml" || name == "action.yaml"
}

// localActionFiles resolves a local `uses: ./path` against root: the
// action.y*ml in that directory, or the file itself if it is a YAML file (a
// local reusable workflow). Paths that leave root, or name nothing, give
// none: there is nothing in this repository to check.
func localActionFiles(root, ref string) []string {
	p := filepath.Join(root, filepath.FromSlash(ref))
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	st, err := os.Stat(p) //nolint:gosec // p stays under root: the ".." check above drops a ref that leaves it
	if err != nil {
		return nil
	}
	if st.Mode().IsRegular() {
		if ext := filepath.Ext(p); ext == ".yml" || ext == ".yaml" {
			return []string{p}
		}
		return nil
	}
	var files []string
	for _, name := range []string{"action.yml", "action.yaml"} {
		f := filepath.Join(p, name)
		if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() { //nolint:gosec // f is in p, which the ".." check keeps under root
			files = append(files, f)
		}
	}
	return files
}
