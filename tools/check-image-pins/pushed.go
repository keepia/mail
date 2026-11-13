package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Verify-pushed mode (`-verify-pushed`, release.yml's push and
// push-rehearsal jobs, #27 B1): the image the push bake step built, and
// in a real run pushed by digest, is the image the build job tested.
//
// The push bake step writes a second output, an OCI layout tar
// (pushed.tar in the workspace; the bake metadata of a push has no config
// digest, review M2). This mode reads:
//   - BAKE_METADATA: that step's metadata (containerimage.digest is the
//     pushed index);
//   - $RUNNER_TEMP/tested/metadata.json: the build row's metadata, from
//     the tested-<image>-<arch> artifact; its containerimage.config.digest
//     is the tested config (-verify-built requires it, and -save has
//     checked that the saved and tested tar holds that config);
//   - BAKE_TARGET, PLATFORM and VERSION from the job env;
//   - pushed.tar, opened only as a regular file: Lstat, then open with
//     O_NOFOLLOW (and O_NONBLOCK, so a FIFO cannot block), then fstat on
//     the descriptor, which must be a regular file and the file Lstat saw.
//
// The push step's metadata names exactly <R>/<repo>:latest (#75, D5):
// the target's tags are the bare repository and buildx reports the OCI
// output's name normalised; R is ghcr.io/keepia (push) or
// localhost:5000/keepia (push-rehearsal's own registry). Any other name
// fails closed, so a buildx change shows in the next dry run. The build
// row's metadata still names ghcr.io/keepia/<repo>:VERSION.
//
// It checks that every blob of the tar has its digest; that index.json
// names exactly one manifest, the metadata's containerimage.digest; that
// this index holds exactly one image manifest, for linux/<arch>, plus only
// attestation manifests that reference it; and that its config is the
// tested config (also for os and architecture). A cache hit proves
// nothing (review M4): only this comparison counts. Then, and only then,
// it reads <R>/<repo>@<index> back from the registry it was pushed to
// (#75, D3; checkRowInRegistry, the row check -publish-index runs): the
// same bytes as the tar's index, the same platform manifest, the tested
// config. A failed read is reported apart from other content (D-e). On
// success it writes $RUNNER_TEMP/digest/<target>-<arch>.json for
// -publish-index, whose repository is R/<repo> (so a rehearsal record
// never feeds -publish-index or attest, D2), and the step outputs index
// and manifest.

// pushedRecord is a push row's result: the digest file -publish-index
// reads.
type pushedRecord struct {
	Target     string `json:"target"`
	Platform   string `json:"platform"`
	Repository string `json:"repository"`
	Version    string `json:"version"`
	Index      string `json:"index"`
	Manifest   string `json:"manifest"`
	Config     string `json:"config"`
}

// pushedInput is what verifyPushed checks.
type pushedInput struct {
	meta, tested              []byte
	target, platform, version string
	tar                       string
	// reg reads the pushed row back (the docker CLI in the job; a fake
	// in tests).
	reg registry
	// afterLstat runs between the Lstat and the open of the tar (tests
	// swap the file there).
	afterLstat func()
}

// registryReadPrefix starts the finding of a failed registry read (D-e),
// so runVerifyPushed and the runbook tell it apart from a mismatch.
const registryReadPrefix = "the registry read failed"

// pushedRepo returns the repository a push step's metadata names: exactly
// one name, <R>/<repo>:latest with R one of the two push registries.
func pushedRepo(b builtImage, target string) (string, string) {
	names := b.names()
	repos := pushRepos(target)
	if len(names) == 1 {
		for _, r := range repos {
			if names[0] == r+":latest" {
				return r, ""
			}
		}
	}
	return "", fmt.Sprintf("the push step's metadata names the images %v, want exactly one of %s:latest or %s:latest (the bare repository the row was pushed to)", names, repos[0], repos[1])
}

// ociDescriptor is an entry of an OCI index.
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Annotations map[string]string `json:"annotations"`
	Platform    *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

// ociIndex is an OCI image index or a Docker manifest list.
type ociIndex struct {
	MediaType   string            `json:"mediaType"`
	Manifests   []ociDescriptor   `json:"manifests"`
	Annotations map[string]string `json:"annotations"`
}

// ociManifest is an image manifest.
type ociManifest struct {
	MediaType string `json:"mediaType"`
	Config    struct {
		Digest string `json:"digest"`
	} `json:"config"`
}

const (
	attestationType = "attestation-manifest"
	refTypeKey      = "vnd.docker.reference.type"
	refDigestKey    = "vnd.docker.reference.digest"
	versionKey      = "org.opencontainers.image.version"
)

// archOf returns the arch of linux/<arch>, or "".
func archOf(platform string) string {
	a, ok := strings.CutPrefix(platform, "linux/")
	if !ok || a == "" || strings.Contains(a, "/") {
		return ""
	}
	return a
}

// targetImage returns the metadata entry of target in bake metadata, with
// a finding if there is none or another target.
func targetImage(meta []byte, target, what string) (builtImage, string) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(meta, &top); err != nil {
		return builtImage{}, fmt.Sprintf("the %s does not parse: %v", what, err)
	}
	var targets []string
	for k, raw := range top {
		if raw = bytes.TrimSpace(raw); len(raw) > 0 && raw[0] == '{' {
			targets = append(targets, k)
		}
	}
	sort.Strings(targets)
	if len(targets) != 1 || targets[0] != target {
		return builtImage{}, fmt.Sprintf("the %s names the targets %v, want exactly %s", what, targets, target)
	}
	var b builtImage
	if err := json.Unmarshal(top[target], &b); err != nil {
		return builtImage{}, fmt.Sprintf("the %s does not parse: %v", what, err)
	}
	return b, ""
}

// openRegular opens p only as a regular file (B5, revision 5): Lstat,
// open with O_NOFOLLOW, then fstat on the descriptor.
func openRegular(p string, afterLstat func()) (*os.File, error) {
	before, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (%s)", p, before.Mode().Type())
	}
	if afterLstat != nil {
		afterLstat()
	}
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	f := os.NewFile(uintptr(fd), p)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(before, st) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed between Lstat and open (now %s): it is read only as the regular file Lstat saw", p, st.Mode().Type())
	}
	return f, nil
}

// readOCITar reads an OCI layout tar: every regular file's sha256, the
// content of the small ones, and a finding for every blob whose content
// is not its digest and every entry that is not a file or directory.
func readOCITar(r io.Reader) (map[string]string, map[string][]byte, []string) {
	sums := map[string]string{}
	small := map[string][]byte{}
	var findings []string
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, append(findings, "pushed.tar does not read: "+err.Error())
		}
		name := path.Clean(h.Name)
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			findings = append(findings, fmt.Sprintf("pushed.tar has %s, which is not a regular file or directory", name))
			continue
		}
		if _, dup := sums[name]; dup {
			findings = append(findings, fmt.Sprintf("pushed.tar has %s twice", name))
		}
		hash := sha256.New()
		var keep bytes.Buffer
		var w io.Writer = hash
		if h.Size <= maxTarMeta {
			w = io.MultiWriter(hash, &keep)
		}
		if _, err := io.Copy(w, tr); err != nil { //nolint:gosec // the tar the job's own bake step wrote; sizes are bounded by the image
			return nil, nil, append(findings, "pushed.tar does not read: "+err.Error())
		}
		sum := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		sums[name] = sum
		if h.Size <= maxTarMeta {
			small[name] = keep.Bytes()
		}
		if hexDigest, ok := strings.CutPrefix(name, "blobs/sha256/"); ok && sum != "sha256:"+hexDigest {
			findings = append(findings, fmt.Sprintf("pushed.tar's blob %s has the content of %s", name, sum))
		}
	}
	return sums, small, findings
}

// blob returns the content of a blob of the tar.
func blob(small map[string][]byte, digest string) ([]byte, bool) {
	b, ok := small["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")]
	return b, ok && imageID.MatchString(digest)
}

// platformImage checks an image index (the content of one pushed row, in
// the tar or the registry): exactly one image manifest, for linux/<arch>,
// plus only attestation manifests that reference it. It returns that
// manifest's digest.
func platformImage(raw []byte, arch string) (string, error) {
	var idx ociIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return "", fmt.Errorf("the index does not parse: %w", err)
	}
	if !isIndexType(idx.MediaType) {
		return "", fmt.Errorf("it is %q, not an image index", idx.MediaType)
	}
	var images, attest []ociDescriptor
	for _, d := range idx.Manifests {
		if d.Annotations[refTypeKey] == attestationType {
			attest = append(attest, d)
		} else {
			images = append(images, d)
		}
	}
	if len(images) != 1 {
		return "", fmt.Errorf("it holds %d image manifests, want exactly one (linux/%s)", len(images), arch)
	}
	img := images[0]
	if img.Platform == nil || img.Platform.OS != "linux" || img.Platform.Architecture != arch || img.Platform.Variant != "" || !imageID.MatchString(img.Digest) {
		return "", fmt.Errorf("its image manifest is not linux/%s: %+v", arch, img.Platform)
	}
	for _, a := range attest {
		if a.Annotations[refDigestKey] != img.Digest {
			return "", fmt.Errorf("its attestation manifest %s references %s, not the image manifest %s", a.Digest, a.Annotations[refDigestKey], img.Digest)
		}
	}
	return img.Digest, nil
}

func isIndexType(t string) bool {
	return t == "application/vnd.oci.image.index.v1+json" || t == "application/vnd.docker.distribution.manifest.list.v2+json"
}

// verifyPushed checks a push row (see the top of the file).
func verifyPushed(in pushedInput) (pushedRecord, []string) {
	var rec pushedRecord
	arch := archOf(in.platform)
	if arch == "" {
		return rec, []string{fmt.Sprintf("PLATFORM %q is not linux/<arch>", in.platform)}
	}
	if !bakeTargetName.MatchString(in.target) {
		return rec, []string{fmt.Sprintf("BAKE_TARGET %q is not a plain target name", in.target)}
	}
	if !semverRE.MatchString(in.version) {
		return rec, []string{fmt.Sprintf("VERSION %q is not X.Y.Z", in.version)}
	}
	wantTested := imageRepo(in.target) + ":" + in.version
	pushed, f := targetImage(in.meta, in.target, "push step's metadata (BAKE_METADATA)")
	if f != "" {
		return rec, []string{f}
	}
	tested, f := targetImage(in.tested, in.target, "build row's metadata (tested-*/metadata.json)")
	if f != "" {
		return rec, []string{f}
	}
	var findings []string
	if !imageID.MatchString(tested.ConfigDigest) {
		findings = append(findings, fmt.Sprintf("the build row's metadata has no containerimage.config.digest (got %q): there is no tested config to compare with", tested.ConfigDigest))
	}
	if !imageID.MatchString(pushed.Digest) {
		findings = append(findings, fmt.Sprintf("the push step's metadata has no containerimage.digest (got %q)", pushed.Digest))
	}
	repo, f := pushedRepo(pushed, in.target)
	if f != "" {
		findings = append(findings, f)
	}
	names := tested.names()
	if len(names) == 0 {
		findings = append(findings, "the build row's metadata names no image")
	}
	for _, n := range names {
		if n != wantTested {
			findings = append(findings, fmt.Sprintf("the build row's metadata names the image %s, want %s", n, wantTested))
		}
	}
	if pushed.ConfigDigest != "" && pushed.ConfigDigest != tested.ConfigDigest {
		findings = append(findings, fmt.Sprintf("the push step's metadata names the config %s, but the tested config is %s", pushed.ConfigDigest, tested.ConfigDigest))
	}
	if len(findings) > 0 {
		return rec, findings
	}

	file, err := openRegular(in.tar, in.afterLstat)
	if err != nil {
		return rec, []string{"pushed.tar is read only as a regular file: " + err.Error()}
	}
	sums, small, tf := readOCITar(file)
	_ = file.Close()
	findings = append(findings, tf...)
	if sums == nil {
		return rec, findings
	}
	var layout ociIndex
	if err := json.Unmarshal(small["index.json"], &layout); err != nil {
		return rec, append(findings, "pushed.tar has no readable index.json: "+err.Error())
	}
	if len(layout.Manifests) != 1 || layout.Manifests[0].Digest != pushed.Digest {
		var got []string
		for _, m := range layout.Manifests {
			got = append(got, m.Digest)
		}
		return rec, append(findings, fmt.Sprintf("pushed.tar's index.json names %v, want exactly the pushed index %s (containerimage.digest)", got, pushed.Digest))
	}
	raw, ok := blob(small, pushed.Digest)
	if !ok {
		return rec, append(findings, fmt.Sprintf("pushed.tar lacks the pushed index %s", pushed.Digest))
	}
	manifestDigest, err := platformImage(raw, arch)
	if err != nil {
		return rec, append(findings, fmt.Sprintf("the pushed index %s: %v", pushed.Digest, err))
	}
	mraw, ok := blob(small, manifestDigest)
	var m ociManifest
	if !ok || json.Unmarshal(mraw, &m) != nil {
		return rec, append(findings, fmt.Sprintf("pushed.tar lacks a readable image manifest %s", manifestDigest))
	}
	if m.Config.Digest != tested.ConfigDigest {
		return rec, append(findings, fmt.Sprintf("the pushed image's config is %s, but the tested config is %s: the push rebuilt something the build job did not test (a cache miss or a step that is not reproducible); in a real run this untested image is in GHCR by digest, untagged: the maintainer deletes it (runbook)", m.Config.Digest, tested.ConfigDigest))
	}
	craw, ok := blob(small, m.Config.Digest)
	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	if !ok || json.Unmarshal(craw, &cfg) != nil || cfg.OS != "linux" || cfg.Architecture != arch {
		return rec, append(findings, fmt.Sprintf("the pushed config %s is not a readable linux/%s config", m.Config.Digest, arch))
	}
	if len(findings) > 0 {
		return rec, findings
	}
	// The registry read, only once every check of the tar has passed.
	if in.reg == nil {
		return rec, []string{"no registry to read the pushed row back from"}
	}
	got, err := checkRowInRegistry(in.reg, repo, arch, pushed.Digest, manifestDigest, tested.ConfigDigest)
	var readErr *registryReadError
	if errors.As(err, &readErr) {
		return rec, []string{fmt.Sprintf("%s: %v. pushed.tar passed every check, so pushed.tar is the tested image; what the registry holds for this row is unknown, because the read failed. This is a read error, not a content mismatch: the coordinator stops and reports, and no package version is deleted for it (runbook)", registryReadPrefix, err)}
	}
	if err == nil && !bytes.Equal(got, raw) {
		err = errors.New("its index bytes differ from pushed.tar's")
	}
	if err != nil {
		return rec, []string{fmt.Sprintf("the registry holds other content than pushed.tar for %s@%s: %v; in a real run an image that is not the tested one may be in GHCR by digest, untagged: the maintainer deletes it (runbook)", repo, pushed.Digest, err)}
	}
	// The record names the repository the row was pushed to (D2).
	return pushedRecord{
		Target: in.target, Platform: in.platform, Repository: repo, Version: in.version,
		Index: pushed.Digest, Manifest: manifestDigest, Config: m.Config.Digest,
	}, nil
}

// digestFile is the path of a push row's digest file under dir.
func digestFile(dir, target, platform string) string {
	return filepath.Join(dir, target+"-"+archOf(platform)+".json")
}

// runVerifyPushed is verify-pushed mode.
func runVerifyPushed(stdout io.Writer) int {
	r := &report{out: stdout}
	// notStarted reports a failure before any comparison, with its own
	// summary line (#51 item 18).
	notStarted := func(path, msg string) int {
		r.add(path, 0, msg)
		fmt.Fprintf(stdout, "check-image-pins: verify-pushed could not start: %s: %s; nothing was compared.\n", path, strings.Join(strings.Fields(msg), " "))
		return 1
	}
	temp := os.Getenv("RUNNER_TEMP")
	if temp == "" {
		return notStarted("RUNNER_TEMP", "empty: verify-pushed runs in a release.yml push job")
	}
	tested, err := os.ReadFile(filepath.Join(temp, "tested", "metadata.json")) //nolint:gosec // the runner's temp directory, the tested-* artifact
	if err != nil {
		return notStarted("tested metadata", err.Error())
	}
	reg, err := pushedRegistry()
	if err != nil {
		return notStarted("registry client", err.Error())
	}
	in := pushedInput{
		meta: []byte(os.Getenv("BAKE_METADATA")), tested: tested,
		target: os.Getenv("BAKE_TARGET"), platform: os.Getenv("PLATFORM"), version: os.Getenv("VERSION"),
		tar: pushedTar, reg: reg,
	}
	rec, findings := verifyPushed(in)
	readFailed := len(findings) > 0
	for _, f := range findings {
		r.add(pushedTar, 0, f)
		readFailed = readFailed && strings.HasPrefix(f, registryReadPrefix)
	}
	switch {
	case readFailed:
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s): the registry read failed after every check of pushed.tar passed; a read error, not a mismatch.\n", r.bad)
		return 1
	case r.bad > 0:
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s): the pushed image is not the tested image.\n", r.bad)
		return 1
	}
	if err := writePushedRecord(filepath.Join(temp, "digest"), rec); err != nil {
		r.add("digest", 0, err.Error())
		return 1
	}
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		for _, l := range []string{"index=" + rec.Index, "manifest=" + rec.Manifest} {
			if err := appendLine(out, l); err != nil {
				r.add("GITHUB_OUTPUT", 0, err.Error())
				return 1
			}
		}
	}
	fmt.Fprintf(stdout, "check-image-pins: pushed config = tested config (%s) for %s %s: index %s, manifest %s; read back from the registry %s.\n",
		rec.Config, rec.Repository, rec.Platform, rec.Index, rec.Manifest, strings.SplitN(rec.Repository, "/", 2)[0])
	return 0
}

// pushedRegistry is the registry -verify-pushed reads the row back from:
// the docker CLI (anonymous on localhost in push-rehearsal, with the
// job's GHCR login in push); tests replace it.
var pushedRegistry = func() (registry, error) { return newDockerRegistry() }

// writePushedRecord writes a push row's digest file into dir.
func writePushedRecord(dir string, rec pushedRecord) error {
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // $RUNNER_TEMP/digest, the runner's own temp directory
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	p := digestFile(dir, rec.Target, rec.Platform)
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s exists already", p)
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}
