package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The two typed tool modes that write tags in GHCR (#27, plan revisions
// 1, 4 and 5). They take no tag argument: X.Y.Z and latest are the only
// tag names in the code. Each builds its docker argv itself, runs the
// docker binary resolved once with a cleaned environment (passEnv), and
// checks everything before it creates anything: a refusal anywhere means
// no `imagetools create` runs at all.
//
// -publish-index (job index), per image of bake's default group:
//  1. the name is the target's only tag ghcr.io/keepia/mail[-<name>]:VERSION
//     from `docker buildx bake --print` with the default REGISTRY;
//  2. each of the two digest files ($RUNNER_TEMP/digest/<target>-<arch>.json,
//     from -verify-pushed) names sha256 digests, and in the registry
//     <name>@<index> is an index with exactly one image manifest for
//     linux/<arch> (plus attestation manifests that reference it) whose
//     config is the tested config;
//  3. X.Y.Z is immutable: if the tag exists and holds exactly the two
//     expected image manifests (and attestations that reference them) and
//     the version annotation, it is a no-op; any other content is refused
//     and never overwritten. "not found" counts as absent only right after
//     the digest checks above reached the same repository;
//  4. then `imagetools create -t <name>:X.Y.Z --annotation
//     index:org.opencontainers.image.version=X.Y.Z <name>@<amd64>
//     <name>@<arm64>`, and the new tag is checked again. It puts out
//     digests, a JSON object of name to index digest.
//
// -move-latest (job latest), forward only:
//  0. before any registry access: `git ls-remote --tags` of the constant
//     URL, from an empty temp directory, with no git config and no
//     inherited GIT_* variable, and a timeout. The highest vX.Y.Z tag
//     (numerically) must be v$VERSION, and its commit (the peeled ^{} line
//     of an annotated tag, else the ref itself) must be GITHUB_SHA;
//  1. X.Y.Z resolves to its digest from INDEX_DIGESTS (the index job's
//     output) and has the two platforms;
//  2. the current latest: absent ("not found", which step 0 makes safe:
//     VERSION is the highest release), or its version from the index
//     annotation and both platform configs' version label, all present,
//     equal and X.Y.Z;
//  3. a newer VERSION moves; the same version with the same digest is a
//     no-op; anything else is refused;
//  4. `imagetools create -t <name>:latest <name>@<digest>`, then latest
//     must resolve to that digest.

// releaseRepoURL is the repository whose tags step 0 reads (public, no
// token).
const releaseRepoURL = "https://github.com/keepia/mail"

// lsRemoteTimeout bounds step 0's git call.
var lsRemoteTimeout = 2 * time.Minute

// registryTimeout bounds one docker call.
const registryTimeout = 5 * time.Minute

var errNotFound = errors.New("not found")

// registry is what the two modes need from GHCR; dockerRegistry is the
// real one, tests use a fake that records what create is called with.
type registry interface {
	// raw is `imagetools inspect --raw ref`: the manifest's exact bytes.
	raw(ref string) ([]byte, error)
	// config is the image config of a single-platform manifest ref.
	config(ref string) ([]byte, error)
	// create is `imagetools create` with these arguments.
	create(args []string) error
}

// dockerRegistry runs docker buildx imagetools.
type dockerRegistry struct {
	bin string
	env []string
}

func newDockerRegistry() (*dockerRegistry, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("cannot find the docker CLI: %w", err)
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return nil, err
	}
	return &dockerRegistry{bin: bin, env: cleanEnv(nil)}, nil
}

func (d *dockerRegistry) docker(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), registryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.bin, args...) //nolint:gosec // the docker CLI resolved once; the argv is built here from constants and checked digests
	cmd.Env = d.env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "not found") {
			return nil, fmt.Errorf("%w: %s", errNotFound, msg)
		}
		return nil, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out, nil
}

func (d *dockerRegistry) raw(ref string) ([]byte, error) {
	return d.docker("buildx", "imagetools", "inspect", "--raw", ref)
}

func (d *dockerRegistry) config(ref string) ([]byte, error) {
	return d.docker("buildx", "imagetools", "inspect", "--format", "{{json .Image}}", ref)
}

func (d *dockerRegistry) create(args []string) error {
	_, err := d.docker(append([]string{"buildx", "imagetools", "create"}, args...)...)
	return err
}

func sha256Of(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// rawDigest fetches ref and checks that its bytes have the digest want
// ("" for a tag: the digest is returned).
func rawDigest(reg registry, ref, want string) ([]byte, string, error) {
	raw, err := reg.raw(ref)
	if err != nil {
		return nil, "", err
	}
	got := sha256Of(raw)
	if want != "" && got != want {
		return nil, "", fmt.Errorf("%s has the content of %s", ref, got)
	}
	return raw, got, nil
}

// releaseIndex checks a published X.Y.Z or latest index: exactly two image
// manifests, linux/amd64 and linux/arm64 (the given ones, when set), plus
// attestation manifests that reference them, and the version annotation
// (when version is set). It returns the image manifests by arch and the
// annotation.
func releaseIndex(raw []byte, want map[string]string, version string) (map[string]string, string, error) {
	var idx ociIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, "", fmt.Errorf("the index does not parse: %w", err)
	}
	if !isIndexType(idx.MediaType) {
		return nil, "", fmt.Errorf("it is %q, not an image index", idx.MediaType)
	}
	images := map[string]string{}
	var attest []ociDescriptor
	for _, d := range idx.Manifests {
		if d.Annotations[refTypeKey] == attestationType {
			attest = append(attest, d)
			continue
		}
		if d.Platform == nil || d.Platform.OS != "linux" || d.Platform.Variant != "" || !imageID.MatchString(d.Digest) {
			return nil, "", fmt.Errorf("it holds an image manifest that is not linux/amd64 or linux/arm64: %s %+v", d.Digest, d.Platform)
		}
		if _, dup := images[d.Platform.Architecture]; dup {
			return nil, "", fmt.Errorf("it holds two linux/%s manifests", d.Platform.Architecture)
		}
		images[d.Platform.Architecture] = d.Digest
	}
	if len(images) != 2 || images["amd64"] == "" || images["arm64"] == "" {
		return nil, "", fmt.Errorf("it holds the image manifests %v, want exactly linux/amd64 and linux/arm64", images)
	}
	for arch, d := range want {
		if images[arch] != d {
			return nil, "", fmt.Errorf("its linux/%s manifest is %s, want %s", arch, images[arch], d)
		}
	}
	for _, a := range attest {
		ref := a.Annotations[refDigestKey]
		if ref != images["amd64"] && ref != images["arm64"] {
			return nil, "", fmt.Errorf("its attestation manifest %s references %s, which is not one of its image manifests", a.Digest, ref)
		}
	}
	got := idx.Annotations[versionKey]
	if version != "" && got != version {
		return nil, "", fmt.Errorf("its annotation %s is %q, want %q", versionKey, got, version)
	}
	return images, got, nil
}

// releaseArchList are the architectures of every released image.
var releaseArchList = []string{"amd64", "arm64"}

// bakeRepos returns the images of bake's default group (target →
// repository), each target's tags exactly the repository at VERSION.
type bakeRepos func(version string) (map[string]string, error)

func realBakeRepos(version string) (map[string]string, error) {
	b := bake{dir: ".", files: rootBakeFiles("."), env: cleanEnv(map[string]string{"VERSION": version})}
	targets, err := b.print(nil, []string{"default"})
	if err != nil {
		return nil, err
	}
	return reposOf(targets, version)
}

// reposOf maps resolved targets to their repositories (rule: the only tag
// is ghcr.io/keepia/mail[-<name>]:VERSION).
func reposOf(targets map[string]bakeTarget, version string) (map[string]string, error) {
	if len(targets) == 0 {
		return nil, errors.New("bake's default group has no target")
	}
	out := map[string]string{}
	for n, t := range targets {
		want := imageRepo(n) + ":" + version
		if len(t.Tags) != 1 || t.Tags[0] != want {
			return nil, fmt.Errorf("target %s has the tags %v, want exactly [%s]", n, t.Tags, want)
		}
		out[n] = imageRepo(n)
	}
	return out, nil
}

// readDigestFiles reads the push rows' digest files of dir: exactly one per
// target and architecture, each for its own target, platform, repository
// and version.
func readDigestFiles(dir string, repos map[string]string, version string) (map[string]map[string]pushedRecord, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{err.Error()}
	}
	want := map[string]bool{}
	for t := range repos {
		for _, a := range releaseArchList {
			want[t+"-"+a+".json"] = true
		}
	}
	var findings []string
	out := map[string]map[string]pushedRecord{}
	for _, e := range entries {
		if !want[e.Name()] || !e.Type().IsRegular() {
			findings = append(findings, fmt.Sprintf("%s: not the digest file of a release image and architecture", e.Name()))
			continue
		}
		delete(want, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // a file of the digest-* artifacts in the runner's temp directory
		if err != nil {
			findings = append(findings, err.Error())
			continue
		}
		var rec pushedRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			findings = append(findings, fmt.Sprintf("%s does not parse: %v", e.Name(), err))
			continue
		}
		arch := archOf(rec.Platform)
		switch {
		case rec.Target+"-"+arch+".json" != e.Name() || repos[rec.Target] != rec.Repository || rec.Version != version:
			findings = append(findings, fmt.Sprintf("%s is for %s %s %s at %s, not for its own name at %s", e.Name(), rec.Target, rec.Repository, rec.Platform, rec.Version, version))
		case !imageID.MatchString(rec.Index) || !imageID.MatchString(rec.Manifest) || !imageID.MatchString(rec.Config):
			findings = append(findings, fmt.Sprintf("%s: a digest is not sha256:<64 hex>", e.Name()))
		default:
			if out[rec.Target] == nil {
				out[rec.Target] = map[string]pushedRecord{}
			}
			out[rec.Target][arch] = rec
		}
	}
	for _, n := range sortedBool(want) {
		findings = append(findings, fmt.Sprintf("%s is missing: every image is pushed for both architectures", n))
	}
	return out, findings
}

// publishDeps are -publish-index's ties to the world.
type publishDeps struct {
	reg   registry
	repos bakeRepos
}

// publishIndex is -publish-index; it returns repository → index digest.
func publishIndex(version, digestDir string, deps publishDeps) (map[string]string, []string) {
	if !semverRE.MatchString(version) {
		return nil, []string{fmt.Sprintf("VERSION %q is not X.Y.Z", version)}
	}
	repos, err := deps.repos(version)
	if err != nil {
		return nil, []string{"the release images: " + err.Error()}
	}
	recs, findings := readDigestFiles(digestDir, repos, version)
	if len(findings) > 0 {
		return nil, findings
	}
	type plan struct {
		repo     string
		manifest map[string]string
		args     []string
		existing string
	}
	var plans []plan
	targets := sortedStrings(repos)
	for _, t := range targets {
		repo := repos[t]
		p := plan{repo: repo, manifest: map[string]string{}}
		var sources []string
		for _, arch := range releaseArchList {
			rec := recs[t][arch]
			raw, _, err := rawDigest(deps.reg, repo+"@"+rec.Index, rec.Index)
			if err != nil {
				findings = append(findings, fmt.Sprintf("%s linux/%s: %v", repo, arch, err))
				continue
			}
			m, err := platformImage(raw, arch)
			if err != nil || m != rec.Manifest {
				findings = append(findings, fmt.Sprintf("%s@%s: %v (want the image manifest %s)", repo, rec.Index, err, rec.Manifest))
				continue
			}
			mraw, _, err := rawDigest(deps.reg, repo+"@"+m, m)
			var man ociManifest
			if err == nil {
				err = json.Unmarshal(mraw, &man)
			}
			if err != nil || man.Config.Digest != rec.Config {
				findings = append(findings, fmt.Sprintf("%s@%s: its config is %q, want the tested config %s (%v)", repo, m, man.Config.Digest, rec.Config, err))
				continue
			}
			p.manifest[arch] = m
			sources = append(sources, repo+"@"+rec.Index)
		}
		if len(p.manifest) != len(releaseArchList) {
			continue
		}
		tag := repo + ":" + version
		raw, digest, err := rawDigest(deps.reg, tag, "")
		switch {
		case errors.Is(err, errNotFound):
			p.args = append([]string{"-t", tag, "--annotation", "index:" + versionKey + "=" + version}, sources...)
		case err != nil:
			findings = append(findings, fmt.Sprintf("%s: %v; refused: it may exist, and X.Y.Z is never overwritten", tag, err))
			continue
		default:
			if _, _, err := releaseIndex(raw, p.manifest, version); err != nil {
				findings = append(findings, fmt.Sprintf("%s exists with other content (%v): X.Y.Z is immutable and never overwritten", tag, err))
				continue
			}
			p.existing = digest
		}
		plans = append(plans, p)
	}
	if len(findings) > 0 {
		return nil, findings
	}
	out := map[string]string{}
	for _, p := range plans {
		tag := p.repo + ":" + version
		if p.args != nil {
			if err := deps.reg.create(p.args); err != nil {
				return nil, []string{fmt.Sprintf("%s: imagetools create: %v", tag, err)}
			}
		}
		raw, digest, err := rawDigest(deps.reg, tag, "")
		if err == nil {
			_, _, err = releaseIndex(raw, p.manifest, version)
		}
		if err != nil {
			return nil, []string{fmt.Sprintf("%s after publishing: %v", tag, err)}
		}
		if p.existing != "" && digest != p.existing {
			return nil, []string{fmt.Sprintf("%s changed during the run: %s, then %s", tag, p.existing, digest)}
		}
		out[p.repo] = digest
	}
	return out, nil
}

func sortedStrings(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// semverLess reports whether a < b, field by field as numbers (both
// X.Y.Z).
func semverLess(a, b string) bool {
	pa, pb := semverFields(a), semverFields(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func semverFields(v string) [3]uint64 {
	var f [3]uint64
	for i, s := range strings.SplitN(v, ".", 3) {
		f[i], _ = strconv.ParseUint(s, 10, 64)
	}
	return f
}

var (
	gitOID     = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	commitSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

// highestTag reads `git ls-remote --tags` output and returns the highest
// vX.Y.Z tag and its commit. A malformed line, or no such tag, is an
// error.
func highestTag(out []byte) (string, string, error) {
	ids := map[string]string{}    // tag → the ref's own id
	peeled := map[string]string{} // tag → its ^{} commit
	text := strings.TrimRight(string(out), "\n")
	if strings.TrimSpace(text) == "" {
		return "", "", errors.New("git ls-remote gave no tags")
	}
	for _, l := range strings.Split(text, "\n") {
		oid, ref, ok := strings.Cut(l, "\t")
		name, isTag := strings.CutPrefix(ref, "refs/tags/")
		if !ok || !gitOID.MatchString(oid) || !isTag || name == "" {
			return "", "", fmt.Errorf("git ls-remote gave a line that is not <id>TAB refs/tags/<name>: %q", l)
		}
		if base, ok := strings.CutSuffix(name, "^{}"); ok {
			peeled[base] = oid
		} else {
			ids[name] = oid
		}
	}
	best := ""
	for name := range ids {
		if versionTag.MatchString(name) && (best == "" || semverLess(best[1:], name[1:])) {
			best = name
		}
	}
	if best == "" {
		return "", "", errors.New("git ls-remote gave no vX.Y.Z tag")
	}
	commit := ids[best]
	if p, ok := peeled[best]; ok {
		commit = p
	}
	return best, commit, nil
}

// gitCommand is step 0's command: the absolute git, the constant URL, an
// empty directory, and only these variables.
func gitCommand(ctx context.Context, git, dir string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, git, "ls-remote", "--tags", "--", releaseRepoURL) //nolint:gosec // git resolved once; the URL is a constant
	cmd.Dir = dir
	// No HOME either: git's HTTP transport would read ~/.netrc.
	env := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	if v, ok := os.LookupEnv("PATH"); ok {
		env = append(env, "PATH="+v)
	}
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// lsRemote runs step 0's git call with lsRemoteTimeout.
func lsRemote() ([]byte, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("cannot find git: %w", err)
	}
	if git, err = filepath.Abs(git); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "keepia-ls-remote-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir) //nolint:errcheck // an empty temp directory
	ctx, cancel := context.WithTimeout(context.Background(), lsRemoteTimeout)
	defer cancel()
	cmd := gitCommand(ctx, git, dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("git ls-remote --tags %s did not answer within %s", releaseRepoURL, lsRemoteTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("git ls-remote --tags %s: %w: %s", releaseRepoURL, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// latestDeps are -move-latest's ties to the world.
type latestDeps struct {
	reg      registry
	repos    bakeRepos
	lsRemote func() ([]byte, error)
}

// moveLatest is -move-latest; it returns what it did per repository.
func moveLatest(version, digests, sha string, deps latestDeps) ([]string, []string) {
	if !semverRE.MatchString(version) {
		return nil, []string{fmt.Sprintf("VERSION %q is not X.Y.Z", version)}
	}
	if !commitSHA.MatchString(sha) {
		return nil, []string{fmt.Sprintf("GITHUB_SHA %q is not a commit id", sha)}
	}
	// Step 0, before any registry access.
	out, err := deps.lsRemote()
	if err != nil {
		return nil, []string{"step 0 (highest release): " + err.Error() + "; latest is not moved"}
	}
	tag, commit, err := highestTag(out)
	if err != nil {
		return nil, []string{"step 0 (highest release): " + err.Error() + "; latest is not moved"}
	}
	if tag != "v"+version {
		return nil, []string{fmt.Sprintf("step 0: the highest release tag is %s, not v%s: latest moves only to the highest release", tag, version)}
	}
	if commit != sha {
		return nil, []string{fmt.Sprintf("step 0: %s points to %s, not to this run's commit %s", tag, commit, sha)}
	}
	repos, err := deps.repos(version)
	if err != nil {
		return nil, []string{"the release images: " + err.Error()}
	}
	var index map[string]string
	if err := json.Unmarshal([]byte(digests), &index); err != nil {
		return nil, []string{fmt.Sprintf("INDEX_DIGESTS does not parse as a JSON object: %v", err)}
	}
	want := map[string]bool{}
	for _, r := range repos {
		want[r] = true
	}
	var findings []string
	for r, d := range index {
		if !want[r] || !imageID.MatchString(d) {
			findings = append(findings, fmt.Sprintf("INDEX_DIGESTS names %s %s, which is not a release image with a sha256 digest", r, d))
		}
	}
	for r := range want {
		if _, ok := index[r]; !ok {
			findings = append(findings, fmt.Sprintf("INDEX_DIGESTS lacks %s", r))
		}
	}
	if len(findings) > 0 {
		return nil, findings
	}
	type move struct{ repo, digest string }
	var moves []move
	var done []string
	for _, repo := range sortedBool(want) {
		digest := index[repo]
		// Step 1: X.Y.Z is the published, checked index.
		raw, _, err := rawDigest(deps.reg, repo+":"+version, digest)
		if err == nil {
			_, _, err = releaseIndex(raw, nil, version)
		}
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s:%s: %v; latest is not moved", repo, version, err))
			continue
		}
		// Step 2: the current latest.
		raw, current, err := rawDigest(deps.reg, repo+":latest", "")
		if errors.Is(err, errNotFound) {
			moves = append(moves, move{repo, digest})
			continue
		}
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s:latest: %v; refused", repo, err))
			continue
		}
		cur, err := latestVersion(deps.reg, repo, raw)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s:latest: %v; refused: the version latest holds is never guessed", repo, err))
			continue
		}
		// Step 3: forward only.
		switch {
		case semverLess(cur, version):
			moves = append(moves, move{repo, digest})
		case cur == version && current == digest:
			done = append(done, fmt.Sprintf("%s:latest is %s already (%s)", repo, version, digest))
		default:
			findings = append(findings, fmt.Sprintf("%s:latest holds %s (%s); moving it to %s (%s) would not be forward: refused", repo, cur, current, version, digest))
		}
	}
	if len(findings) > 0 {
		return nil, findings
	}
	for _, m := range moves {
		if err := deps.reg.create([]string{"-t", m.repo + ":latest", m.repo + "@" + m.digest}); err != nil {
			return done, []string{fmt.Sprintf("%s:latest: imagetools create: %v", m.repo, err)}
		}
		if _, _, err := rawDigest(deps.reg, m.repo+":latest", m.digest); err != nil {
			return done, []string{fmt.Sprintf("%s:latest after the move: %v", m.repo, err)}
		}
		done = append(done, fmt.Sprintf("%s:latest moved to %s (%s)", m.repo, version, m.digest))
	}
	sort.Strings(done)
	return done, nil
}

// latestVersion reads the version latest holds: the index annotation and
// both platform configs' version label, all present, equal and X.Y.Z.
func latestVersion(reg registry, repo string, raw []byte) (string, error) {
	images, annotation, err := releaseIndex(raw, nil, "")
	if err != nil {
		return "", err
	}
	if !semverRE.MatchString(annotation) {
		return "", fmt.Errorf("its index annotation %s is %q, not X.Y.Z", versionKey, annotation)
	}
	for _, arch := range releaseArchList {
		b, err := reg.config(repo + "@" + images[arch])
		if err != nil {
			return "", fmt.Errorf("the linux/%s config does not read: %w", arch, err)
		}
		var cfg struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return "", fmt.Errorf("the linux/%s config does not parse: %w", arch, err)
		}
		if l := cfg.Config.Labels[versionKey]; l != annotation {
			return "", fmt.Errorf("the linux/%s config's label %s is %q, but the index annotation is %q", arch, versionKey, l, annotation)
		}
	}
	return annotation, nil
}

// runPublishIndex is -publish-index.
func runPublishIndex(stdout io.Writer) int {
	r := &report{out: stdout}
	reg, err := newDockerRegistry()
	if err != nil {
		r.add("publish-index", 0, err.Error())
		return 1
	}
	digests, findings := publishIndex(os.Getenv("VERSION"), filepath.Join(os.Getenv("RUNNER_TEMP"), "digest"), publishDeps{reg: reg, repos: realBakeRepos})
	for _, f := range findings {
		r.add("publish-index", 0, f)
	}
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s); see above for what was published.\n", r.bad)
		return 1
	}
	b, err := json.Marshal(digests)
	if err != nil {
		r.add("publish-index", 0, err.Error())
		return 1
	}
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		if err := appendLine(out, "digests="+string(b)); err != nil {
			r.add("GITHUB_OUTPUT", 0, err.Error())
			return 1
		}
	}
	for _, repo := range sortedStrings(digests) {
		fmt.Fprintf(stdout, "%s:%s %s\n", repo, os.Getenv("VERSION"), digests[repo])
	}
	fmt.Fprintf(stdout, "check-image-pins: %d image indexes published and checked.\n", len(digests))
	return 0
}

// runMoveLatest is -move-latest.
func runMoveLatest(stdout io.Writer) int {
	r := &report{out: stdout}
	reg, err := newDockerRegistry()
	if err != nil {
		r.add("move-latest", 0, err.Error())
		return 1
	}
	done, findings := moveLatest(os.Getenv("VERSION"), os.Getenv("INDEX_DIGESTS"), os.Getenv("GITHUB_SHA"),
		latestDeps{reg: reg, repos: realBakeRepos, lsRemote: lsRemote})
	for _, d := range done {
		fmt.Fprintln(stdout, d)
	}
	for _, f := range findings {
		r.add("move-latest", 0, f)
	}
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s); latest is not moved further.\n", r.bad)
		return 1
	}
	fmt.Fprintf(stdout, "check-image-pins: latest is %s for %d images.\n", os.Getenv("VERSION"), len(done))
	return 0
}
