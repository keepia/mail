package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Local mode (`-bake-local`), the only local image build path (`make
// images`): the tool builds the bake argv itself, resolves --print with
// exactly that argv and environment, checks the result, and then runs
// `docker buildx bake` with the same argv and environment. Whatever the
// caller's shell or Makefile holds, bake sees only:
//   - the root's default bake files, with --file;
//   - --set lines from the typed options below, nothing else;
//   - a cleaned environment plus VERSION, REGISTRY and PLATFORM.
//
// The options a local build behind a TLS-inspecting proxy needs, and
// what each adds:
//   - -ca FILE: --set *.secrets=id=ca,src=FILE and --allow fs.read=DIR;
//   - -host-network: --set *.network=host and --allow network.host (the
//     build reaches a proxy on the host's loopback);
//   - -https-proxy URL: --set *.args.HTTPS_PROXY=URL (a predefined build
//     argument, kept out of the image history).

// localOptions are the typed options of local mode.
type localOptions struct {
	version, registry, platform string
	ca                          string
	hostNetwork                 bool
	httpsProxy                  string
	dryRun                      bool
	targets                     []string
}

var (
	proxyURL     = regexp.MustCompile(`^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$`)
	localVarText = regexp.MustCompile(`^[A-Za-z0-9_./:-]*$`)
)

// localPlan is a validated local build: the bake runner and the --set,
// --allow and target arguments.
type localPlan struct {
	b       bake
	sets    []string
	allows  []string
	names   []string
	policy  targetPolicy
	problem []string
}

func planLocal(root string, o localOptions) localPlan {
	var p localPlan
	vars := map[string]string{}
	for k, v := range map[string]string{"VERSION": o.version, "REGISTRY": o.registry, "PLATFORM": o.platform} {
		if v == "" {
			continue
		}
		if !localVarText.MatchString(v) {
			p.problem = append(p.problem, fmt.Sprintf("-%s %q has characters outside %s", strings.ToLower(k), v, localVarText))
			continue
		}
		vars[k] = v
	}
	if o.ca != "" {
		abs, err := filepath.Abs(o.ca)
		st, serr := os.Stat(abs) //nolint:gosec // the CA bundle the developer names for the build
		switch {
		case err != nil || serr != nil || !st.Mode().IsRegular():
			p.problem = append(p.problem, fmt.Sprintf("-ca %q is not a readable file", o.ca))
		case strings.ContainsAny(abs, ",\"'\n="):
			p.problem = append(p.problem, fmt.Sprintf("-ca %q: the path may not hold , \" ' = or a newline", abs))
		default:
			p.sets = append(p.sets, "*.secrets=id=ca,src="+abs)
			p.allows = append(p.allows, "--allow", "fs.read="+filepath.Dir(abs))
			p.policy.secretSrc = abs
		}
	}
	if o.hostNetwork {
		p.sets = append(p.sets, "*.network=host")
		p.allows = append(p.allows, "--allow", "network.host")
		p.policy.hostNetwork = true
	}
	if o.httpsProxy != "" {
		if !proxyURL.MatchString(o.httpsProxy) {
			p.problem = append(p.problem, fmt.Sprintf("-https-proxy %q is not http(s)://host[:port]", o.httpsProxy))
		} else {
			p.sets = append(p.sets, "*.args.HTTPS_PROXY="+o.httpsProxy)
		}
	}
	names := o.targets
	if len(names) == 0 {
		names = []string{"default"}
	}
	var bad []string
	p.names, bad = plainNames(names)
	p.problem = append(p.problem, bad...)
	p.b = bake{dir: root, files: rootBakeFiles(root), env: cleanEnv(vars)}
	// One docker binary for the resolve and the build (#46, B N3): its
	// absolute path, looked up once in this process's PATH.
	if bin, err := exec.LookPath("docker"); err != nil {
		p.problem = append(p.problem, "cannot find the docker CLI: "+err.Error())
	} else if p.b.bin, err = filepath.Abs(bin); err != nil {
		p.problem = append(p.problem, "cannot resolve the docker CLI's path: "+err.Error())
	}
	if len(p.b.files) == 0 {
		p.problem = append(p.problem, "no bake file at the repository root")
	}
	return p
}

// runLocal is local mode: plan, resolve, check, then build with the same
// argv and environment.
func runLocal(root string, o localOptions, stdout, stderr io.Writer) int {
	p := planLocal(root, o)
	r := &report{out: stdout}
	label := "bake local (" + strings.Join(p.names, ",") + ")"
	for _, m := range p.problem {
		r.add(label, 0, m)
	}
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s); nothing built.\n", r.bad)
		return 1
	}
	resolved, err := p.b.print(p.sets, p.names)
	if err != nil {
		r.add(label, 0, "cannot resolve the bake definition: "+err.Error())
	} else {
		findings, refs := CheckBakeTargets(root, resolved, p.policy)
		for _, f := range findings {
			r.add(label, 0, f)
		}
		checkDockerfiles(r, root, label, refs)
	}
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s) in the definition this build would use; nothing built.\n", r.bad)
		return 1
	}
	buildArgs := append([]string{}, p.allows...)
	for _, s := range p.sets {
		buildArgs = append(buildArgs, "--set", s)
	}
	buildArgs = append(buildArgs, "--load", "--")
	buildArgs = append(buildArgs, p.names...)
	argv := p.b.argv(buildArgs...)
	fmt.Fprintf(stdout, "check-image-pins: the definition is pinned; running %s %s\n", p.b.bin, strings.Join(argv, " "))
	if o.dryRun {
		return 0
	}
	cmd := exec.Command(p.b.bin, argv...) //nolint:gosec // the docker CLI resolved once in planLocal, with the argv checked above: default files, typed --set lines, plain target names
	cmd.Dir = root
	cmd.Env = p.b.env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(stderr, "check-image-pins: docker buildx bake: %v\n", err)
		return 1
	}
	return 0
}

// checkDockerfiles applies rules 1-3 to every Dockerfile a resolved
// definition names, once each, inside root.
func checkDockerfiles(r *report, root, label string, refs []string) int {
	seen := map[string]bool{}
	for _, df := range refs {
		df = filepath.Clean(df)
		if seen[df] {
			continue
		}
		seen[df] = true
		rel, err := filepath.Rel(root, df)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			r.add(label, 0, "names a Dockerfile outside the repository: "+df)
			continue
		}
		src, err := os.ReadFile(df) //nolint:gosec // df is named by the repository's own bake definition, inside root
		if err != nil {
			r.add(df, 0, err.Error())
			continue
		}
		r.addAll(df, CheckDockerfile(src))
	}
	return len(seen)
}
