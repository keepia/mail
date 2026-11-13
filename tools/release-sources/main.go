// Command release-sources writes the SBOMs and the source list of a
// release (#27 plan section 3 and revision 2 E; the licence decision
// 6835095391). Standard library only.
//
//	release-sources row -target T -platform linux/A -version X.Y.Z -commit SHA \
//	    -metadata tested/metadata.json -syft syft.json -spdx syft.spdx.json \
//	    [-packages packages.txt] -out DIR
//
// Row mode runs in a build row of release.yml, after -verify-built -save
// and syft (v1.57.1, on the saved and checked tar). It writes
// DIR/sbom-<image>-<arch>.spdx.json (syft's SPDX 2.3 document, its subject
// the verified config digest and platform, plus one package per ADD
// download and one for Keepia's own files) and DIR/sources-<image>-<arch>.json
// (the row's source list). It fails closed (buildRow): the SBOM's image
// (syft's source imageID) must be the tested config; every packages.txt
// row (name, version, arch) a deb package of the SBOM and every deb
// package in packages.txt, and the Keepia image (distroless, no
// packages.txt) must have at least distrolessBase; every ADD --checksum
// of the target's Dockerfile must match one URL form of addForms and have
// a licence in addLicences; every RUN of an image Dockerfile without
// --network=none must be exactly `sh /tmp/keepia-apt-install
// <package>...` with the helper's bind mount (and the optional ca
// secret), read as the instruction joined over its continuation lines
// (R1; the root Dockerfile's Go build stage is the one named exception);
// each image must have its requiredComponents; and the target must have
// an org.opencontainers.image.licenses label and an
// io.github.keepia.sources label naming this release's SOURCES.md.
//
// Release mode:
//
//	release-sources release -version X.Y.Z -in DIR -digests DIR -out DIR
//
// It runs in the bundle job. It requires exactly one SBOM and
// source list per image of bake's default group and architecture
// (amd64, arm64), each for the config the push row proved
// (DIR/<target>-<arch>.json from -verify-pushed), and writes sources.json,
// SOURCES.md and licences.txt (image and label, for the release notes)
// into -out, and a summary table on stdout.
//
// Debian sources are https://snapshot.debian.org/package/<source>/<version>/
// references, built as text and never contacted.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const (
	registry   = "ghcr.io/keepia"
	syftTool   = "Tool: syft-v1.57.1"
	ownTool    = "Tool: keepia-release-sources"
	repoURL    = "https://github.com/keepia/mail"
	licenceKey = "org.opencontainers.image.licenses"
	sourcesKey = "io.github.keepia.sources"
)

var (
	semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	targetRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	archs    = []string{"amd64", "arm64"}
	aptPkgRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	checksum = regexp.MustCompile(`^--checksum=sha256:([0-9a-f]{64})$`)
	addForms = []addForm{
		{"github-tag", regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/archive/refs/tags/([A-Za-z0-9_.-]+)\.tar\.gz$`)},
		{"github-commit", regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/archive/([0-9a-f]{40})\.tar\.gz$`)},
		{"pypi-wheel", regexp.MustCompile(`^https://files\.pythonhosted\.org/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/([A-Za-z0-9_.]+)-([0-9][A-Za-z0-9_.]*)-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$`)},
	}
)

// addForm is a URL form an ADD may download from; any other form fails the
// tool, so a new download cannot go unlisted.
type addForm struct {
	kind string
	re   *regexp.Regexp
}

// addLicences are the declared licences of the ADD components, by name
// (GitHub owner/repo or PyPI project), as the bake file's comments derive
// them from the pinned sources (#55, #59, #25).
var addLicences = map[string]string{
	"Alinto/sope":           "LGPL-2.0-or-later",
	"Alinto/sogo":           "GPL-2.0-or-later",
	"HeinleinSupport/olefy": "Apache-2.0",
	"oletools":              "BSD-2-Clause AND MIT AND PSF-2.0 AND CC-BY-SA-3.0 AND BSD-3-Clause AND GPL-3.0-only AND LicenseRef-Public-Domain",
	"pcodedmp":              "GPL-3.0-only",
}

// requiredComponents are the components each image must list besides its
// Debian packages (the coverage argument, revision 2 E).
var requiredComponents = map[string][]string{
	"keepia": {"go-toolchain:go", "go-module:*"},
	"olefy":  {"download:HeinleinSupport/olefy", "download:oletools", "download:pcodedmp"},
	"sogo":   {"download:Alinto/sope", "download:Alinto/sogo"},
}

// distrolessBase are the Debian packages of the pinned
// gcr.io/distroless/static-debian13:nonroot base (its status.d, read with
// syft in #27 part 4a).
var distrolessBase = []string{"base-files", "ca-certificates", "media-types", "netbase", "tzdata", "tzdata-legacy"}

// component is one entry of a source list.
type component struct {
	Kind          string   `json:"kind"` // debian, download, go-module, go-toolchain, keepia
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Arch          string   `json:"arch,omitempty"`
	Source        string   `json:"source,omitempty"`
	SourceVersion string   `json:"sourceVersion,omitempty"`
	URL           string   `json:"url"`
	SHA256        string   `json:"sha256,omitempty"`
	H1            string   `json:"h1,omitempty"`
	License       string   `json:"license,omitempty"`
	Images        []string `json:"images,omitempty"`
}

func (c component) key() string {
	return strings.Join([]string{c.Kind, c.Name, c.Version, c.Arch}, "\x00")
}

// rowSources is a row's source list.
type rowSources struct {
	Image      string      `json:"image"`
	Target     string      `json:"target"`
	Platform   string      `json:"platform"`
	Version    string      `json:"version"`
	Config     string      `json:"config"`
	Licenses   string      `json:"licenses"`
	Packages   int         `json:"packages"`
	Components []component `json:"components"`
}

// imageName is the GHCR repository name of a target.
func imageName(target string) string {
	if target == "keepia" {
		return "mail"
	}
	return "mail-" + target
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: release-sources row|release [flags]")
		return 2
	}
	switch args[0] {
	case "row":
		return runRow(args[1:], stdout, stderr)
	case "release":
		return runRelease(args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, "usage: release-sources row|release [flags]")
	return 2
}

// bakeTarget is what the tool reads of a resolved target.
type bakeTarget struct {
	Context    string            `json:"context"`
	Dockerfile string            `json:"dockerfile"`
	Labels     map[string]string `json:"labels"`
	Tags       []string          `json:"tags"`
}

// resolve runs `docker buildx bake --print` for names in a cleaned
// environment with VERSION, as check-image-pins does.
var resolve = func(version string, names ...string) (map[string]bakeTarget, error) {
	env := []string{"VERSION=" + version}
	for _, k := range []string{"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cmd := exec.Command("docker", append([]string{"buildx", "bake", "--progress=quiet", "--print", "--"}, names...)...) //nolint:gosec // target names match targetRE
	cmd.Env = env
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker buildx bake --print: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	var printed struct {
		Target map[string]bakeTarget `json:"target"`
	}
	if err := json.Unmarshal(out, &printed); err != nil {
		return nil, err
	}
	return printed.Target, nil
}

func readFile(p string) ([]byte, error) {
	return os.ReadFile(p) //nolint:gosec // the tool's own arguments: files of the release job
}

// rowInput is what row mode checks and turns into an SBOM and a source
// list.
type rowInput struct {
	target, platform, version, commit string
	tested, syft, spdx, packages      []byte
	hasPackages                       bool
	dockerfile                        []byte
	dockerfilePath                    string // relative to the repository root
	labels                            map[string]string
}

func runRow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("release-sources row", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var in rowInput
	var meta, syft, spdx, pkgs, out string
	fs.StringVar(&in.target, "target", "", "the bake target")
	fs.StringVar(&in.platform, "platform", "", "linux/<arch>")
	fs.StringVar(&in.version, "version", "", "the release version X.Y.Z")
	fs.StringVar(&in.commit, "commit", "", "the release commit (GITHUB_SHA)")
	fs.StringVar(&meta, "metadata", "", "the build row's bake metadata")
	fs.StringVar(&syft, "syft", "", "syft's syft-json of the saved tar")
	fs.StringVar(&spdx, "spdx", "", "syft's spdx-json of the saved tar")
	fs.StringVar(&pkgs, "packages", "", "the image's /usr/share/keepia/packages.txt (none for keepia)")
	fs.StringVar(&out, "out", "", "the output directory")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || out == "" || meta == "" || syft == "" || spdx == "" {
		fmt.Fprintln(stderr, "usage: release-sources row -target T -platform linux/A -version X.Y.Z -commit SHA -metadata F -syft F -spdx F [-packages F] -out DIR")
		return 2
	}
	if !targetRE.MatchString(in.target) || !semverRE.MatchString(in.version) {
		fmt.Fprintf(stderr, "release-sources: target %q or version %q is not valid\n", in.target, in.version)
		return 2
	}
	var err error
	for _, f := range []struct {
		p string
		b *[]byte
	}{{meta, &in.tested}, {syft, &in.syft}, {spdx, &in.spdx}} {
		if *f.b, err = readFile(f.p); err != nil {
			fmt.Fprintln(stderr, "release-sources:", err)
			return 1
		}
	}
	if pkgs != "" {
		in.hasPackages = true
		if in.packages, err = readFile(pkgs); err != nil {
			fmt.Fprintln(stderr, "release-sources:", err)
			return 1
		}
	}
	targets, err := resolve(in.version, in.target)
	if err != nil {
		fmt.Fprintln(stderr, "release-sources:", err)
		return 1
	}
	t, ok := targets[in.target]
	if !ok {
		fmt.Fprintf(stderr, "release-sources: bake has no target %s\n", in.target)
		return 1
	}
	in.labels = t.Labels
	in.dockerfilePath = path.Clean(path.Join(t.Context, t.Dockerfile))
	if t.Dockerfile == "" {
		in.dockerfilePath = path.Clean(path.Join(t.Context, "Dockerfile"))
	}
	if strings.HasPrefix(in.dockerfilePath, "../") || path.IsAbs(in.dockerfilePath) {
		fmt.Fprintf(stderr, "release-sources: the Dockerfile %s is outside the repository\n", in.dockerfilePath)
		return 1
	}
	if in.dockerfile, err = readFile(filepath.FromSlash(in.dockerfilePath)); err != nil {
		fmt.Fprintln(stderr, "release-sources:", err)
		return 1
	}
	sbom, src, findings := buildRow(in)
	for _, f := range findings {
		fmt.Fprintf(stdout, "release-sources: %s %s: %s\n", in.target, in.platform, f)
	}
	if len(findings) > 0 {
		return 1
	}
	if err := writeRow(out, sbom, src); err != nil {
		fmt.Fprintln(stderr, "release-sources:", err)
		return 1
	}
	fmt.Fprintf(stdout, "release-sources: %s %s: %d SBOM packages, %d sources, config %s.\n", src.Image, src.Platform, src.Packages, len(src.Components), src.Config)
	return 0
}

func rowFile(kind, image, arch string) string {
	if kind == "sbom" {
		return "sbom-" + image + "-" + arch + ".spdx.json"
	}
	return "sources-" + image + "-" + arch + ".json"
}

func writeRow(out string, sbom []byte, src rowSources) error {
	if err := os.MkdirAll(out, 0o750); err != nil { //nolint:gosec // the tool's output directory argument
		return err
	}
	arch := strings.TrimPrefix(src.Platform, "linux/")
	b, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, rowFile("sbom", src.Image, arch)), sbom, 0o644); err != nil { //nolint:gosec // a release asset
		return err
	}
	return os.WriteFile(filepath.Join(out, rowFile("sources", src.Image, arch)), append(b, '\n'), 0o644) //nolint:gosec // a release asset
}

// syftDoc is what the tool reads of syft's syft-json.
type syftDoc struct {
	Artifacts []struct {
		Type         string `json:"type"`
		Name         string `json:"name"`
		Version      string `json:"version"`
		MetadataType string `json:"metadataType"`
		Metadata     struct {
			Package           string `json:"package"`
			Source            string `json:"source"`
			SourceVersion     string `json:"sourceVersion"`
			Architecture      string `json:"architecture"`
			H1Digest          string `json:"h1Digest"`
			GoCompiledVersion string `json:"goCompiledVersion"`
			MainModule        string `json:"mainModule"`
		} `json:"metadata"`
	} `json:"artifacts"`
	Source struct {
		Type     string `json:"type"`
		Metadata struct {
			ImageID string `json:"imageID"`
		} `json:"metadata"`
	} `json:"source"`
}

// buildRow checks a row and returns its SPDX document and source list.
func buildRow(in rowInput) ([]byte, rowSources, []string) {
	var findings []string
	bad := func(format string, a ...any) { findings = append(findings, fmt.Sprintf(format, a...)) }
	arch, ok := strings.CutPrefix(in.platform, "linux/")
	if !ok || (arch != "amd64" && arch != "arm64") {
		return nil, rowSources{}, []string{fmt.Sprintf("platform %q is not linux/amd64 or linux/arm64", in.platform)}
	}
	if !commitRE.MatchString(in.commit) {
		bad("commit %q is not a commit id", in.commit)
	}
	image := imageName(in.target)
	src := rowSources{Image: image, Target: in.target, Platform: in.platform, Version: in.version}

	// The tested config: the build row's metadata entry of the target
	// (other keys, such as buildx.build.warnings, are not objects).
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(in.tested, &meta); err != nil {
		return nil, src, []string{"the build metadata does not parse: " + err.Error()}
	}
	var entry struct {
		Config string `json:"containerimage.config.digest"`
	}
	_ = json.Unmarshal(meta[in.target], &entry)
	src.Config = entry.Config
	if !digestRE.MatchString(src.Config) {
		return nil, src, []string{fmt.Sprintf("the build metadata has no containerimage.config.digest for %s", in.target)}
	}

	var sd syftDoc
	if err := json.Unmarshal(in.syft, &sd); err != nil {
		return nil, src, []string{"syft's syft-json does not parse: " + err.Error()}
	}
	if sd.Source.Metadata.ImageID != src.Config {
		bad("the SBOM is of the image %q, not the tested config %s", sd.Source.Metadata.ImageID, src.Config)
	}

	// Labels.
	src.Licenses = in.labels[licenceKey]
	if strings.TrimSpace(src.Licenses) == "" {
		bad("the target has no %s label", licenceKey)
	}
	wantSources := fmt.Sprintf("%s/releases/download/v%s/SOURCES.md", repoURL, in.version)
	if got := in.labels[sourcesKey]; got != wantSources {
		bad("the target's %s label is %q, want %q", sourcesKey, got, wantSources)
	}

	// Debian packages: the SBOM against packages.txt.
	debs := map[string]component{}
	var comps []component
	for _, a := range sd.Artifacts {
		switch a.Type {
		case "deb":
			c := component{Kind: "debian", Name: a.Name, Version: a.Version, Arch: a.Metadata.Architecture,
				Source: a.Metadata.Source, SourceVersion: a.Metadata.SourceVersion}
			if c.Source == "" {
				c.Source = c.Name
			}
			if c.SourceVersion == "" {
				c.SourceVersion = c.Version
			}
			c.URL = "https://snapshot.debian.org/package/" + snapshotEscape(c.Source) + "/" + snapshotEscape(c.SourceVersion) + "/"
			if _, dup := debs[c.Name+"\t"+c.Version+"\t"+c.Arch]; dup {
				continue
			}
			debs[c.Name+"\t"+c.Version+"\t"+c.Arch] = c
			comps = append(comps, c)
		case "go-module":
			m := a.Metadata
			if a.Name == "stdlib" {
				comps = append(comps, component{Kind: "go-toolchain", Name: "go", Version: a.Version,
					URL: "https://go.dev/dl/" + a.Version + ".src.tar.gz", License: "BSD-3-Clause"})
				continue
			}
			if a.Name == m.MainModule {
				continue // Keepia's own code: the keepia/mail component
			}
			comps = append(comps, component{Kind: "go-module", Name: a.Name, Version: a.Version, H1: m.H1Digest,
				URL: "https://proxy.golang.org/" + moduleEscape(a.Name) + "/@v/" + moduleEscape(a.Version) + ".zip"})
		default:
			bad("the SBOM has a %s package (%s), which the source list does not cover", a.Type, a.Name)
		}
	}
	if in.hasPackages {
		listed := map[string]bool{}
		for i, l := range strings.Split(strings.TrimRight(string(in.packages), "\n"), "\n") {
			f := strings.Split(l, "\t")
			if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" {
				bad("packages.txt line %d is not name<TAB>version<TAB>arch: %q", i+1, l)
				continue
			}
			key := strings.Join(f, "\t")
			listed[key] = true
			if _, ok := debs[key]; !ok {
				bad("packages.txt lists %s %s %s, which is not a deb package of the SBOM", f[0], f[1], f[2])
			}
		}
		for _, k := range sortedKeys(debs) {
			if !listed[k] {
				c := debs[k]
				bad("the SBOM has the deb package %s %s %s, which packages.txt does not list", c.Name, c.Version, c.Arch)
			}
		}
	} else {
		if in.target != "keepia" {
			bad("no packages.txt: only the Keepia image (distroless) has none")
		}
		for _, n := range distrolessBase {
			found := false
			for _, c := range debs {
				found = found || c.Name == n
			}
			if !found {
				bad("the SBOM lacks the distroless base package %s", n)
			}
		}
	}

	// The Dockerfile: ADD downloads and networked RUNs.
	adds, df := checkDockerfile(in.dockerfilePath, in.dockerfile)
	findings = append(findings, df...)
	comps = append(comps, adds...)
	own := component{Kind: "keepia", Name: "keepia/mail", Version: in.commit, URL: repoURL + "/tree/" + in.commit, License: "MIT"}
	comps = append(comps, own)

	have := map[string]bool{}
	for _, c := range comps {
		have[c.Kind+":"+c.Name] = true
		if c.Kind == "go-module" {
			have["go-module:*"] = true
		}
	}
	for _, r := range requiredComponents[in.target] {
		if !have[r] {
			bad("the image lacks its component %s", r)
		}
	}
	src.Components = comps
	if len(findings) > 0 {
		return nil, src, findings
	}
	sbom, n, err := finishSPDX(in.spdx, in, image, arch, src.Config, adds, own)
	if err != nil {
		return nil, src, []string{err.Error()}
	}
	src.Packages = n
	return sbom, src, nil
}

// snapshotEscape escapes a Debian name or version for a snapshot URL:
// everything but letters, digits and . ~ _ - (an epoch's : is %3A, + is
// %2B).
func snapshotEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '~', c == '_', c == '-':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// moduleEscape is the module proxy's case encoding: an upper-case letter
// is ! and its lower case.
func moduleEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// instruction is a Dockerfile instruction joined over its continuation
// lines (comment lines inside are dropped, as Docker does).
type instruction struct {
	line int
	text string
}

func instructions(src []byte) []instruction {
	var out []instruction
	var cur strings.Builder
	start := 0
	for i, l := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(l)
		if cur.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			start = i + 1
		} else if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(l, "\\") {
			cur.WriteString(strings.TrimSuffix(l, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(l)
		out = append(out, instruction{start, strings.TrimSpace(cur.String())})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, instruction{start, strings.TrimSpace(cur.String())})
	}
	return out
}

const aptMount = "--mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install"
const caMount = "--mount=type=secret,id=ca,required=false,mode=0444"

// checkDockerfile returns the ADD components of a Dockerfile and its
// findings (ADD forms, networked RUNs).
func checkDockerfile(rel string, src []byte) ([]component, []string) {
	var comps []component
	var findings []string
	bad := func(line int, format string, a ...any) {
		findings = append(findings, fmt.Sprintf("%s:%d: %s", rel, line, fmt.Sprintf(format, a...)))
	}
	stage, stageImage := "", ""
	for _, in := range instructions(src) {
		words := strings.Fields(in.text)
		switch strings.ToUpper(words[0]) {
		case "FROM":
			stage, stageImage = "", ""
			rest := words[1:]
			for len(rest) > 0 && strings.HasPrefix(rest[0], "--") {
				rest = rest[1:]
			}
			if len(rest) > 0 {
				stageImage = rest[0]
			}
			if len(rest) == 3 && strings.EqualFold(rest[1], "AS") {
				stage = rest[2]
			}
		case "ADD":
			var sum string
			var args []string
			for _, w := range words[1:] {
				if m := checksum.FindStringSubmatch(w); m != nil {
					sum = m[1]
				} else if !strings.HasPrefix(w, "--") {
					args = append(args, w)
				}
			}
			if len(args) != 2 || !strings.HasPrefix(args[0], "https://") {
				bad(in.line, "an ADD that is not one https URL and a destination")
				continue
			}
			c, err := addComponent(args[0], sum)
			if err != nil {
				bad(in.line, "%v", err)
				continue
			}
			comps = append(comps, c)
		case "RUN":
			if rel == "Dockerfile" && stage == "build" && strings.HasPrefix(stageImage, "golang:") {
				continue // the root Dockerfile's Go build: go.sum-pinned modules only
			}
			if msg := runProblem(words[1:]); msg != "" {
				bad(in.line, "%s", msg)
			}
		}
	}
	return comps, findings
}

// runProblem checks a RUN's flags and command: --network=none, or exactly
// the keepia-apt-install form.
func runProblem(words []string) string {
	var flags []string
	i := 0
	for i < len(words) && strings.HasPrefix(words[i], "--") {
		flags = append(flags, words[i])
		i++
	}
	for _, f := range flags {
		if f == "--network=none" {
			return ""
		}
	}
	cmd := words[i:]
	okFlags := len(flags) >= 1 && flags[0] == aptMount && (len(flags) == 1 || (len(flags) == 2 && flags[1] == caMount))
	okCmd := len(cmd) >= 3 && cmd[0] == "sh" && cmd[1] == "/tmp/keepia-apt-install"
	for _, p := range cmd[min(2, len(cmd)):] {
		okCmd = okCmd && aptPkgRE.MatchString(p)
	}
	if okFlags && okCmd {
		return ""
	}
	return fmt.Sprintf("a RUN without --network=none must be exactly `RUN %s [%s] sh /tmp/keepia-apt-install <package>...` (package names [a-z0-9][a-z0-9+.-]*, nothing else): %q", aptMount, caMount, strings.Join(words, " "))
}

// addComponent turns an ADD URL into its component, or fails for a URL of
// no known form or without a licence.
func addComponent(url, sum string) (component, error) {
	if sum == "" {
		return component{}, fmt.Errorf("ADD %s has no --checksum=sha256", url)
	}
	for _, f := range addForms {
		m := f.re.FindStringSubmatch(url)
		if m == nil {
			continue
		}
		c := component{Kind: "download", URL: url, SHA256: "sha256:" + sum}
		switch f.kind {
		case "github-tag", "github-commit":
			c.Name, c.Version = m[1]+"/"+m[2], m[3]
		case "pypi-wheel":
			c.Name, c.Version = strings.ReplaceAll(strings.ToLower(m[1]), "_", "-"), m[2]
		}
		lic, ok := addLicences[c.Name]
		if !ok {
			return component{}, fmt.Errorf("ADD %s: %s has no licence in addLicences", url, c.Name)
		}
		c.License = lic
		return c, nil
	}
	return component{}, fmt.Errorf("ADD %s matches no known URL form (GitHub tag archive, GitHub commit archive, PyPI wheel): add the form and its source to release-sources", url)
}

// finishSPDX turns syft's SPDX document into the release SBOM: the creator
// with syft's version, the image (config digest, platform) as the
// described package, and a package for every ADD download and for
// Keepia's own files. It returns the document and its package count.
func finishSPDX(raw []byte, in rowInput, image, arch, config string, adds []component, own component) ([]byte, int, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("syft's spdx-json does not parse: %w", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		return nil, 0, fmt.Errorf("syft's spdx-json is %v, not SPDX-2.3", doc["spdxVersion"])
	}
	repo := registry + "/" + image
	doc["name"] = repo + "@" + config + " linux/" + arch
	doc["documentNamespace"] = fmt.Sprintf("%s/releases/download/v%s/%s", repoURL, in.version, rowFile("sbom", image, arch))
	ci, _ := doc["creationInfo"].(map[string]any)
	if ci == nil {
		return nil, 0, errors.New("syft's spdx-json has no creationInfo")
	}
	var creators []any
	for _, c := range asList(ci["creators"]) {
		if s, _ := c.(string); strings.HasPrefix(s, "Tool: syft-") {
			continue
		}
		creators = append(creators, c)
	}
	ci["creators"] = append(creators, syftTool, ownTool)

	var rootID string
	for _, r := range asList(doc["relationships"]) {
		m, _ := r.(map[string]any)
		if m["relationshipType"] == "DESCRIBES" && m["spdxElementId"] == "SPDXRef-DOCUMENT" {
			if rootID != "" {
				return nil, 0, errors.New("syft's spdx-json describes more than one package")
			}
			rootID, _ = m["relatedSpdxElement"].(string)
		}
	}
	packages := asList(doc["packages"])
	found := false
	for _, p := range packages {
		m, _ := p.(map[string]any)
		if m["SPDXID"] != rootID {
			continue
		}
		found = true
		hexDigest := strings.TrimPrefix(config, "sha256:")
		m["name"] = repo
		m["versionInfo"] = config
		m["checksums"] = []any{map[string]any{"algorithm": "SHA256", "checksumValue": hexDigest}}
		m["externalRefs"] = []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
			"referenceLocator": fmt.Sprintf("pkg:oci/%s@sha256%%3A%s?arch=%s&repository_url=%s", image, hexDigest, arch, repo)}}
		m["comment"] = "The image is named by its config digest, the build row's tested config, which the push row proved equal to the published platform image's."
	}
	if !found {
		return nil, 0, errors.New("syft's spdx-json has no described image package")
	}
	rels := asList(doc["relationships"])
	for i, c := range append(append([]component{}, adds...), own) {
		id := fmt.Sprintf("SPDXRef-Package-keepia-source-%d", i+1)
		p := map[string]any{
			"name": c.Name, "SPDXID": id, "versionInfo": c.Version, "supplier": "NOASSERTION",
			"downloadLocation": c.URL, "filesAnalyzed": false, "licenseConcluded": "NOASSERTION",
			"licenseDeclared": c.License, "copyrightText": "NOASSERTION",
		}
		if c.SHA256 != "" {
			p["checksums"] = []any{map[string]any{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(c.SHA256, "sha256:")}}
		}
		if c.Kind == "keepia" {
			p["downloadLocation"] = "git+" + repoURL + "@" + c.Version
			p["comment"] = "Keepia's own files, copied from the repository at the release commit."
		} else {
			p["comment"] = "Downloaded by ADD --checksum in " + in.dockerfilePath + " and built or installed into the image."
		}
		packages = append(packages, p)
		rels = append(rels, map[string]any{"spdxElementId": rootID, "relatedSpdxElement": id, "relationshipType": "CONTAINS"})
	}
	doc["packages"] = packages
	doc["relationships"] = rels
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return nil, 0, err
	}
	return append(b, '\n'), len(packages), nil
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// digestRecord is what release mode reads of -verify-pushed's digest file.
type digestRecord struct {
	Target   string `json:"target"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Config   string `json:"config"`
}

func runRelease(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("release-sources release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", "", "the release version X.Y.Z")
	inDir := fs.String("in", "", "the directory with every row's sbom-*.spdx.json and sources-*.json")
	digests := fs.String("digests", "", "the push rows' digest files (-verify-pushed)")
	out := fs.String("out", "", "the output directory")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *inDir == "" || *digests == "" || *out == "" || !semverRE.MatchString(*version) {
		fmt.Fprintln(stderr, "usage: release-sources release -version X.Y.Z -in DIR -digests DIR -out DIR")
		return 2
	}
	targets, err := resolve(*version, "default")
	if err != nil {
		fmt.Fprintln(stderr, "release-sources:", err)
		return 1
	}
	files, findings := mergeRelease(*version, sortedKeys(targets), *inDir, *digests)
	for _, f := range findings {
		fmt.Fprintln(stdout, "release-sources:", f)
	}
	if len(findings) > 0 {
		return 1
	}
	if err := os.MkdirAll(*out, 0o750); err != nil { //nolint:gosec // the tool's output directory argument
		fmt.Fprintln(stderr, "release-sources:", err)
		return 1
	}
	for _, name := range sortedKeys(files) {
		if name == "summary" {
			continue
		}
		if err := os.WriteFile(filepath.Join(*out, name), files[name], 0o644); err != nil { //nolint:gosec // a release asset
			fmt.Fprintln(stderr, "release-sources:", err)
			return 1
		}
	}
	_, _ = stdout.Write(files["summary"])
	return 0
}

// mergeRelease checks the rows of a release and returns the files to write
// (sources.json, SOURCES.md, licences.txt, and "summary").
func mergeRelease(version string, targets []string, inDir, digestDir string) (map[string][]byte, []string) {
	var findings []string
	bad := func(format string, a ...any) { findings = append(findings, fmt.Sprintf(format, a...)) }
	want := map[string]bool{}
	for _, t := range targets {
		for _, a := range archs {
			want[rowFile("sbom", imageName(t), a)] = true
			want[rowFile("sources", imageName(t), a)] = true
		}
	}
	entries, err := os.ReadDir(inDir)
	if err != nil {
		return nil, []string{err.Error()}
	}
	for _, e := range entries {
		n := e.Name()
		if (strings.HasPrefix(n, "sbom-") || strings.HasPrefix(n, "sources-")) && !want[n] {
			bad("%s is not a row of this release (images %s × amd64, arm64)", n, strings.Join(targets, ", "))
		}
	}
	merged := map[string]*component{}
	var rows []rowSources
	for _, t := range targets {
		for _, a := range archs {
			image := imageName(t)
			sp := filepath.Join(inDir, rowFile("sbom", image, a))
			sb, err := readFile(sp)
			if err != nil {
				bad("no SBOM for %s linux/%s: %v", image, a, err)
				continue
			}
			srcb, err := readFile(filepath.Join(inDir, rowFile("sources", image, a)))
			if err != nil {
				bad("no source list for %s linux/%s: %v", image, a, err)
				continue
			}
			var src rowSources
			if err := json.Unmarshal(srcb, &src); err != nil {
				bad("the source list of %s linux/%s does not parse: %v", image, a, err)
				continue
			}
			db, err := readFile(filepath.Join(digestDir, t+"-"+a+".json"))
			var rec digestRecord
			if err == nil {
				err = json.Unmarshal(db, &rec)
			}
			if err != nil {
				bad("no push record for %s linux/%s: %v", image, a, err)
				continue
			}
			subject := sbomSubject(sb)
			switch {
			case src.Image != image || src.Platform != "linux/"+a || src.Version != version:
				bad("the source list %s is for %s %s %s", rowFile("sources", image, a), src.Image, src.Platform, src.Version)
			case rec.Target != t || rec.Platform != "linux/"+a || rec.Version != version:
				bad("the push record of %s linux/%s is for %s %s %s", image, a, rec.Target, rec.Platform, rec.Version)
			case !digestRE.MatchString(rec.Config) || src.Config != rec.Config || subject != rec.Config:
				bad("%s linux/%s: the SBOM is of %q and the source list of %q, but the push row proved the published config %q", image, a, subject, src.Config, rec.Config)
			}
			rows = append(rows, src)
			for _, c := range src.Components {
				k := c.key()
				if merged[k] == nil {
					cc := c
					cc.Images = nil
					merged[k] = &cc
				}
				merged[k].Images = append(merged[k].Images, image+" linux/"+a)
			}
		}
	}
	if len(findings) > 0 {
		return nil, findings
	}
	var list []component
	for _, k := range sortedKeys(merged) {
		list = append(list, *merged[k])
	}
	sj, err := json.MarshalIndent(map[string]any{"version": version, "images": rows, "sources": list}, "", "  ")
	if err != nil {
		return nil, []string{err.Error()}
	}
	return map[string][]byte{
		"sources.json": append(sj, '\n'),
		"SOURCES.md":   renderSources(version, rows, list),
		"licences.txt": licences(rows),
		"summary":      summary(version, rows),
	}, nil
}

// sbomSubject is the config digest an SBOM names as its image.
func sbomSubject(b []byte) string {
	var doc struct {
		Packages []struct {
			SPDXID      string `json:"SPDXID"`
			VersionInfo string `json:"versionInfo"`
		} `json:"packages"`
		Relationships []struct {
			From string `json:"spdxElementId"`
			To   string `json:"relatedSpdxElement"`
			Type string `json:"relationshipType"`
		} `json:"relationships"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	for _, r := range doc.Relationships {
		if r.Type == "DESCRIBES" && r.From == "SPDXRef-DOCUMENT" {
			for _, p := range doc.Packages {
				if p.SPDXID == r.To {
					return p.VersionInfo
				}
			}
		}
	}
	return ""
}

func licences(rows []rowSources) []byte {
	var b strings.Builder
	seen := map[string]bool{}
	for _, r := range rows {
		if !seen[r.Image] {
			seen[r.Image] = true
			fmt.Fprintf(&b, "%s %s\n", r.Image, r.Licenses)
		}
	}
	return []byte(b.String())
}

func summary(version string, rows []rowSources) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "| Image %s | linux/amd64 | linux/arm64 |\n|---|---|---|\n", version)
	cells := map[string]map[string]string{}
	var images []string
	for _, r := range rows {
		if cells[r.Image] == nil {
			cells[r.Image] = map[string]string{}
			images = append(images, r.Image)
		}
		cells[r.Image][r.Platform] = fmt.Sprintf("%d packages, %d sources", r.Packages, len(r.Components))
	}
	for _, i := range images {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", i, cells[i]["linux/amd64"], cells[i]["linux/arm64"])
	}
	fmt.Fprintf(&b, "\n%d SBOMs, each for the config the push row proved.\n", len(rows))
	return []byte(b.String())
}

// renderSources writes SOURCES.md: the licence labels, the attribution and
// GPL notes, and every source by kind.
func renderSources(version string, rows []rowSources, list []component) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sources of Keepia Mail %s\n\n", version)
	fmt.Fprintf(&b, "Every file in the images of this release comes from one of the sources below: a Debian package, an `ADD --checksum` download, a Go module, the Go toolchain, or Keepia's own repository at the release commit. The SBOMs (`sbom-<image>-<arch>.spdx.json`, SPDX 2.3) list the same per image and architecture; `sources.json` is this list as data.\n\n")
	b.WriteString("## Licences\n\n| Image | `org.opencontainers.image.licenses` |\n|---|---|\n")
	seen := map[string]bool{}
	for _, r := range rows {
		if !seen[r.Image] {
			seen[r.Image] = true
			fmt.Fprintf(&b, "| `%s/%s:%s` | `%s` |\n", registry, r.Image, version, r.Licenses)
		}
	}
	b.WriteString("\nThe per-package licences of the Debian packages are in the SBOMs.\n\n")
	b.WriteString("The GPL-3.0-only parts of `mail-olefy` (pcodedmp, and xxxswf in oletools' `thirdparty/`) ship with their Python sources and licence files in the image; the wheels are listed below with their sha256.\n\n")
	b.WriteString("**CC-BY-SA-3.0 attribution:** `IterStream` in oletools' `oletools/ppt_record_parser.py` (in `mail-olefy`) is, as its docstring says, \"Copied from stackoverflow answer by Mechanical snail from Nov 18th 2013 https://stackoverflow.com/a/20260030/4405656 and extended.\"\n\n")
	b.WriteString("Verify an image's SBOM attestation with `gh attestation verify oci://ghcr.io/keepia/<image>@<platform digest> --owner keepia --predicate-type https://spdx.dev/Document/v2.3`.\n")
	sections := []struct{ kind, title, head string }{
		{"keepia", "Keepia Mail", "| Component | Commit | Licence |\n|---|---|---|\n"},
		{"download", "Downloads (`ADD --checksum`)", "| Component | Version | Source | sha256 | Licence | Images |\n|---|---|---|---|---|---|\n"},
		{"go-toolchain", "Go toolchain", "| Version | Source | Images |\n|---|---|---|\n"},
		{"go-module", "Go modules", "| Module | Version | Hash | Source |\n|---|---|---|---|\n"},
		{"debian", "Debian packages", "| Package | Version | Arch | Source package | Source version | Images |\n|---|---|---|---|---|---|\n"},
	}
	for _, s := range sections {
		fmt.Fprintf(&b, "\n## %s\n\n%s", s.title, s.head)
		for _, c := range list {
			if c.Kind != s.kind {
				continue
			}
			imgs := strings.Join(c.Images, ", ")
			switch s.kind {
			case "keepia":
				fmt.Fprintf(&b, "| [%s](%s) | `%s` | %s |\n", c.Name, c.URL, c.Version, c.License)
			case "download":
				fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` | `%s` | %s |\n", c.Name, c.Version, c.URL, c.SHA256, c.License, imgs)
			case "go-toolchain":
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n", c.Version, c.URL, imgs)
			case "go-module":
				fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", c.Name, c.Version, c.H1, c.URL)
			case "debian":
				fmt.Fprintf(&b, "| %s | `%s` | %s | [%s](%s) | `%s` | %s |\n", c.Name, c.Version, c.Arch, c.Source, c.URL, c.SourceVersion, imgs)
			}
		}
	}
	return []byte(b.String())
}
