// Command check-image-pins checks that every image and download a build
// uses is pinned, and that only the release workflow can push packages:
//
//  1. a Dockerfile's `# syntax=` is name:X.Y.Z@sha256:<64 hex>;
//  2. every FROM, COPY --from= and RUN --mount=...,from= names an earlier
//     stage or name:tag@sha256:<64 hex>;
//  3. every ADD from http(s):// has --checksum=sha256:<64 hex>; ADD of a
//     git URL, and an ADD source with a variable, are reported;
//  4. a Compose file's services: image by digest, or a build of an image
//     named exactly ${KEEPIA_REGISTRY:-ghcr.io/keepia}/mail[-<name>]...
//     from a local context;
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
	"flag"
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
	kindStrayHCL
	kindMakefile
	kindScript
	kindAction
)

// hclAllowlist lists HCL files (relative to the root) that are not bake
// files and may stay: none today. Any other *.hcl than the root's
// docker-bake.hcl and docker-bake.override.hcl is reported, because a
// build could be pointed at it with --file.
var hclAllowlist = map[string]bool{}

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
	case strings.HasPrefix(dir+"/", ".github/actions/") && (lower == "action.yml" || lower == "action.yaml"):
		return kindAction
	case lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile"):
		return kindDockerfile
	case (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose")) &&
		(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return kindCompose
	case strings.HasSuffix(lower, ".hcl"):
		if dir == "." && (base == "docker-bake.hcl" || base == "docker-bake.override.hcl") {
			return kindBake
		}
		if hclAllowlist[filepath.ToSlash(rel)] {
			return kindNone
		}
		return kindStrayHCL
	case strings.HasPrefix(lower, "docker-bake") && strings.HasSuffix(lower, ".json"):
		return kindBakeJSON
	case lower == "makefile" || lower == "gnumakefile" || strings.HasSuffix(lower, ".mk"):
		return kindMakefile
	case strings.HasSuffix(lower, ".sh"):
		return kindScript
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
	flags := flag.NewFlagSet("check-image-pins", flag.ContinueOnError)
	flags.SetOutput(stderr)
	build := flags.String("build", "", "build mode: the bake targets one build step builds (space or comma separated)")
	buildSet := flags.String("build-set", "", "build mode: that step's --set values, one per line")
	verify := flags.Bool("verify-built", false, "verify mode: the local images are the output in $BAKE_METADATA")
	save := flags.String("save", "", "verify mode: save the verified images to this tar file and check the tar")
	local := flags.Bool("bake-local", false, "local mode: check, then build the given targets (default: the default group)")
	var lo localOptions
	flags.StringVar(&lo.version, "version", "", "local mode: the bake variable VERSION")
	flags.StringVar(&lo.registry, "registry", "", "local mode: the bake variable REGISTRY")
	flags.StringVar(&lo.platform, "platform", "", "local mode: the bake variable PLATFORM")
	flags.StringVar(&lo.ca, "ca", "", "local mode: a CA bundle file, passed as the BuildKit secret ca")
	flags.BoolVar(&lo.hostNetwork, "host-network", false, "local mode: build on the host network")
	flags.StringVar(&lo.httpsProxy, "https-proxy", "", "local mode: the HTTPS_PROXY build argument, http(s)://host[:port]")
	flags.BoolVar(&lo.dryRun, "dry-run", false, "local mode: check and print the bake command, do not build")
	localRoot := flags.String("root", ".", "local mode: the repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case *verify:
		if *local || *build != "" || flags.NArg() > 0 {
			fmt.Fprintln(stderr, "usage: check-image-pins -verify-built [-save FILE]")
			return 2
		}
		return runVerify(*save, realVerifyDeps, stdout)
	case *save != "":
		fmt.Fprintln(stderr, "check-image-pins: -save needs -verify-built")
		return 2
	case *local:
		if *build != "" || *buildSet != "" {
			fmt.Fprintln(stderr, "check-image-pins: -bake-local takes no -build or -build-set")
			return 2
		}
		lo.targets = flags.Args()
		return runLocal(*localRoot, lo, stdout, stderr)
	case lo.version != "" || lo.registry != "" || lo.platform != "" || lo.ca != "" ||
		lo.hostNetwork || lo.httpsProxy != "" || lo.dryRun || *localRoot != ".":
		fmt.Fprintln(stderr, "check-image-pins: -version, -registry, -platform, -ca, -host-network, -https-proxy, -dry-run and -root need -bake-local")
		return 2
	}
	root := "."
	switch flags.NArg() {
	case 0:
	case 1:
		root = flags.Arg(0)
	default:
		fmt.Fprintln(stderr, "usage: check-image-pins [-build TARGETS [-build-set SETS]] [root]")
		return 2
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() { //nolint:gosec // root is the tool's own argument: the tree to check
		fmt.Fprintf(stderr, "check-image-pins: no directory %s\n", root)
		return 2
	}
	if *build != "" {
		return runBuild(root, *build, *buildSet, stdout)
	}
	if *buildSet != "" {
		fmt.Fprintln(stderr, "check-image-pins: -build-set needs -build")
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

	for _, p := range files[kindBakeJSON] {
		r.add(p, 0, "a JSON bake file is not read by this check; use docker-bake.hcl")
	}
	for _, p := range files[kindStrayHCL] {
		r.add(p, 0, "an HCL file that is not the root's docker-bake.hcl or docker-bake.override.hcl: a build could be pointed at it with --file; remove it or list it in hclAllowlist")
	}
	// The bake definition a default `docker buildx bake` reads: every
	// default file present at the root, Compose files included.
	var rootBake []string
	for _, name := range defaultBakeFiles {
		if st, err := os.Stat(filepath.Join(root, name)); err == nil && st.Mode().IsRegular() { //nolint:gosec // a fixed default file name under root
			rootBake = append(rootBake, name)
		}
	}
	if len(rootBake) > 0 {
		label := filepath.Join(root, strings.Join(rootBake, ","))
		findings, refs := checkRepoBake(root, rootBake)
		for _, f := range findings {
			r.add(label, 0, f)
		}
		for _, df := range refs {
			if inRoot(label, df) {
				dockerfiles[filepath.Clean(df)] = true
			}
		}
	}
	// Other build paths: Makefiles, composite actions and scripts. A script
	// is any *.sh, and any file a workflow, action or Makefile names in a
	// command, whatever its name.
	var commandTexts []string
	for _, p := range files[kindMakefile] {
		src, err := os.ReadFile(p) //nolint:gosec // p is a file found by walking root
		if err != nil {
			r.add(p, 0, err.Error())
			continue
		}
		r.addAll(p, CheckMakefile(src))
		commandTexts = append(commandTexts, string(src))
	}
	for _, p := range files[kindAction] {
		src, err := os.ReadFile(p) //nolint:gosec // p is a file found by walking root
		if err != nil {
			r.add(p, 0, err.Error())
			continue
		}
		findings, runs, err := CheckAction(src)
		if err != nil {
			r.add(p, 0, "does not parse: "+err.Error())
			continue
		}
		r.addAll(p, findings)
		commandTexts = append(commandTexts, runs...)
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
			findings, runs, err := CheckWorkflow(src, k == kindReleaseWorkflow, func(text, workdir string, shell bool) ([]refText, []string) {
				return referencedTexts(root, text, workdir, shell)
			})
			if err != nil {
				r.add(p, 0, "does not parse: "+err.Error())
				continue
			}
			r.addAll(p, findings)
			commandTexts = append(commandTexts, runs...)
		}
	}

	scripts := map[string]bool{}
	for _, p := range files[kindScript] {
		scripts[filepath.Clean(p)] = true
	}
	for _, t := range commandTexts {
		for _, p := range referencedFiles(root, t) {
			if classify(mustRel(root, p)) == kindNone {
				scripts[filepath.Clean(p)] = true
			}
		}
	}
	var scriptList []string
	for p := range scripts {
		scriptList = append(scriptList, p)
	}
	sort.Strings(scriptList)
	for _, p := range scriptList {
		src, err := os.ReadFile(p) //nolint:gosec // p is a script under root
		if err != nil {
			r.add(p, 0, err.Error())
			continue
		}
		r.addAll(p, CheckScriptText(src))
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

// runBuild is build mode: it resolves what one build step builds (its
// targets and --set lines, in this process's environment and with
// buildx's own file lookup, as docker/bake-action runs it), then applies
// rule 5 and rules 1-3 to every Dockerfile it names.
func runBuild(root, targets, sets string, stdout io.Writer) int {
	names := strings.Fields(strings.ReplaceAll(targets, ",", " "))
	var setLines []string
	for _, l := range strings.Split(sets, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			setLines = append(setLines, l)
		}
	}
	r := &report{out: stdout}
	label := "bake build (" + strings.Join(names, ",") + ")"
	findings, refs := checkBuildBake(root, names, setLines)
	for _, f := range findings {
		r.add(label, 0, f)
	}
	n := checkDockerfiles(r, root, label, refs)
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s) in the definition of build %s.\n", r.bad, strings.Join(names, ","))
		return 1
	}
	fmt.Fprintf(stdout, "check-image-pins: build %s resolves to pinned images and sources (%d Dockerfiles, %d --set lines).\n",
		strings.Join(names, ","), n, len(setLines))
	return 0
}

// mustRel is p relative to root (p itself if that fails).
func mustRel(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}
