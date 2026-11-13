package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Verify mode (`-verify-built`, CI): the images a job tests and uploads
// are the ones the checked build produced. It reads docker/bake-action's
// metadata output (BAKE_METADATA) and compares, for every image name a
// target built, the local image ID with the digest the build reported.
// Anything that replaced or re-tagged the image after the build (another
// build, a docker tag, a docker load) makes the IDs differ, whatever
// produced it (review B delta 2, D2).
//
// The local ID is the manifest digest with Docker's containerd image
// store, and the config digest with the classic store; the metadata has
// containerimage.digest, and containerimage.config.digest only when the
// load exports in "docker image format": that is the docker-container
// driver's --load into a daemon with the classic store (CI's runners,
// Docker 28 with overlay2). Into a daemon with the containerd image store
// the load exports in "oci image format" and the metadata has no config
// digest (measured in #71 review A, N1, Docker 29.9.2); so does the docker
// driver on that store. Verify requires the config digest (#27, B1 (b)):
// it is the tested config a release push is compared with, and a save
// must hold exactly that config. If the runners move to the containerd
// store, -verify-built fails closed, in CI and in the release, until this
// is reworked.
//
// Verify only proves the store's state at the moment it runs (#46, B
// N1). So what a job tests and saves never goes by tag after it:
//   - with GITHUB_OUTPUT set and one verified image, verify puts out its
//     local ID as `image`, and the test step runs that ID; a later
//     re-tag of the name does not change the image an ID names;
//   - -save FILE saves the verified names itself and then checks the
//     tar it wrote: every blob's content matches its digest, each name
//     has one entry in manifest.json and one in index.json that agree,
//     its image is the checked build's output (its config is the build's
//     config digest), and its layers are
//     that image's (checkTarName, #49 point 6). Only then is the tar
//     renamed to FILE.

type builtImage struct {
	Name         string `json:"image.name"`
	Digest       string `json:"containerimage.digest"`
	ConfigDigest string `json:"containerimage.config.digest"`
}

// names are the image names of a built target.
func (b builtImage) names() []string {
	var out []string
	for _, n := range strings.Split(b.Name, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

var imageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// verifyBuilt checks metadata against inspect (image name → local ID). It
// returns the findings, the built images and the distinct local IDs it
// saw verified.
func verifyBuilt(meta []byte, inspect func(string) (string, error)) ([]string, []builtImage, []string) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(meta, &top); err != nil {
		return []string{fmt.Sprintf("the build metadata does not parse: %v", err)}, nil, nil
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var findings []string
	var images []builtImage
	var ids []string
	checked := 0
	for _, target := range keys {
		raw := bytes.TrimSpace(top[target])
		if len(raw) == 0 || raw[0] != '{' {
			continue // e.g. buildx.build.warnings
		}
		var b builtImage
		if err := json.Unmarshal(raw, &b); err != nil {
			findings = append(findings, fmt.Sprintf("target %q: metadata does not parse: %v", target, err))
			continue
		}
		if len(b.names()) == 0 || (b.Digest == "" && b.ConfigDigest == "") {
			findings = append(findings, fmt.Sprintf("target %q: the metadata names no image or digest", target))
			continue
		}
		// The tested image is the build's config digest (#27, B1 (b)): the
		// release compares the pushed config with it, and with the
		// containerd store the local ID is the manifest digest instead.
		if !imageID.MatchString(b.ConfigDigest) {
			findings = append(findings, fmt.Sprintf("target %q: the metadata has no containerimage.config.digest (sha256:<64 hex>), got %q: the tested config cannot be named", target, b.ConfigDigest))
			continue
		}
		images = append(images, b)
		for _, name := range b.names() {
			checked++
			id, err := inspect(name)
			switch {
			case err != nil:
				findings = append(findings, fmt.Sprintf("target %q: image %s is not in the local store: %v", target, name, err))
			case id != b.Digest && id != b.ConfigDigest:
				findings = append(findings, fmt.Sprintf("target %q: image %s is %s, but the checked build produced %s (config %s): it was replaced after the build", target, name, id, b.Digest, b.ConfigDigest))
			case !slices.Contains(ids, id):
				ids = append(ids, id)
			}
		}
	}
	if checked == 0 && len(findings) == 0 {
		findings = append(findings, "the build metadata names no image")
	}
	return findings, images, ids
}

// familiarName is an image name without Docker Hub's implicit prefix, as
// docker save writes it in RepoTags.
func familiarName(n string) string {
	n = strings.TrimPrefix(n, "docker.io/")
	return strings.TrimPrefix(n, "library/")
}

// maxTarMeta bounds the files verifySavedTar keeps in memory: index.json,
// manifest.json, and blobs up to this size (manifests, indexes, configs).
const maxTarMeta = 4 << 20

// verifySavedTar checks a `docker save` tar of images: every
// blobs/sha256/<hex> file's content has that digest, and every name of
// every image passes checkTarName: in manifest.json with the checked
// build's config and that image's layers, and in index.json (when there
// is one) as one entry that names the same config.
func verifySavedTar(r io.Reader, images []builtImage) []string {
	var findings []string
	sums := map[string]string{}  // file name → sha256:<hex> of its content
	small := map[string][]byte{} // file name → content, for small files
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return append(findings, "the saved tar does not read: "+err.Error())
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		hash := sha256.New()
		var keep bytes.Buffer
		var w io.Writer = hash
		if h.Size <= maxTarMeta {
			w = io.MultiWriter(hash, &keep)
		}
		if _, err := io.Copy(w, tr); err != nil { //nolint:gosec // the tar docker save just wrote; sizes are bounded by the image
			return append(findings, "the saved tar does not read: "+err.Error())
		}
		sum := "sha256:" + hex.EncodeToString(hash.Sum(nil))
		sums[name] = sum
		if h.Size <= maxTarMeta {
			small[name] = keep.Bytes()
		}
		if hexDigest, ok := strings.CutPrefix(name, "blobs/sha256/"); ok && sum != "sha256:"+hexDigest {
			findings = append(findings, fmt.Sprintf("the saved tar's blob %s has the content of %s", name, sum))
		}
	}
	var manifest []struct {
		Config   string
		RepoTags []string
		Layers   []string
	}
	if err := json.Unmarshal(small["manifest.json"], &manifest); err != nil {
		return append(findings, "the saved tar has no readable manifest.json: "+err.Error())
	}
	// index.json is what the containerd image store loads, manifest.json
	// what the classic store loads; older docker save writes no index.json.
	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	_, hasIndex := sums["index.json"]
	if hasIndex {
		if err := json.Unmarshal(small["index.json"], &index); err != nil {
			return append(findings, "the saved tar's index.json does not read: "+err.Error())
		}
	}
	for _, img := range images {
		for _, name := range img.names() {
			findings = append(findings, checkTarName(name, img, manifestEntries(manifest, name), index.Manifests, hasIndex, sums, small)...)
		}
	}
	return findings
}

type tarManifestEntry = struct {
	Config   string
	RepoTags []string
	Layers   []string
}

type tarIndexEntry = struct {
	Digest      string            `json:"digest"`
	Annotations map[string]string `json:"annotations"`
}

// manifestEntries are manifest.json's entries that name an image.
func manifestEntries(manifest []tarManifestEntry, name string) []tarManifestEntry {
	fam := familiarName(name)
	var out []tarManifestEntry
	for _, m := range manifest {
		if slices.ContainsFunc(m.RepoTags, func(t string) bool { return familiarName(t) == fam }) {
			out = append(out, m)
		}
	}
	return out
}

// checkTarName checks one name of a saved tar (#49 point 6):
//   - manifest.json has exactly one entry for it, and index.json (when
//     there is one) exactly one: the loaders take one of several, the
//     classic store the last of manifest.json, the containerd store the
//     last of index.json;
//   - the index entry names, through its manifests, the config that
//     manifest.json names, so both stores load the same image;
//   - that config is the checked build's config digest;
//   - manifest.json's layers are the image's: each layer file's content
//     is the config's diff_id at that position (an uncompressed layer)
//     or the layer the index entry's manifest names there. Every file is
//     hashed, also one outside blobs/.
func checkTarName(name string, img builtImage, entries []tarManifestEntry, index []tarIndexEntry, hasIndex bool, sums map[string]string, small map[string][]byte) []string {
	if len(entries) == 0 {
		return []string{fmt.Sprintf("the saved tar has no image named %s", name)}
	}
	if len(entries) > 1 {
		return []string{fmt.Sprintf("the saved tar's manifest.json has %d entries for %s, want exactly one", len(entries), name)}
	}
	m := entries[0]
	config := sums[path.Clean(m.Config)]
	if config == "" {
		return []string{fmt.Sprintf("the saved tar lacks the config %s of %s", m.Config, name)}
	}
	var manifest *tarImage
	digest := ""
	if hasIndex {
		fam := familiarName(name)
		var named []tarIndexEntry
		for _, e := range index {
			if familiarName(e.Annotations["io.containerd.image.name"]) == fam {
				named = append(named, e)
			}
		}
		if len(named) != 1 {
			return []string{fmt.Sprintf("the saved tar's index.json has %d entries for %s, want exactly one", len(named), name)}
		}
		digest = named[0].Digest
		for _, t := range tarImages(small, digest, 0) {
			if t.config == config {
				manifest = &t
				break
			}
		}
		if manifest == nil {
			return []string{fmt.Sprintf("the saved tar's index.json entry for %s (%s) does not name the config manifest.json names (%s): the two image stores would load different images", name, digest, config)}
		}
	}
	var findings []string
	// The saved image's config is the build's config digest, which verify
	// requires: the tested config of a release row (#27, B1 (b)).
	if config != img.ConfigDigest {
		findings = append(findings, fmt.Sprintf("the saved tar's %s has config %s, which is not the checked build's output (digest %s, config %s): it was replaced after the build", name, config, img.Digest, img.ConfigDigest))
	}
	var cfg struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(small[path.Clean(m.Config)], &cfg); err != nil {
		return append(findings, fmt.Sprintf("the saved tar's config %s of %s does not read: %v", m.Config, name, err))
	}
	if len(m.Layers) != len(cfg.RootFS.DiffIDs) {
		return append(findings, fmt.Sprintf("the saved tar names %d layers for %s, but its config has %d", len(m.Layers), name, len(cfg.RootFS.DiffIDs)))
	}
	for i, l := range m.Layers {
		sum := sums[path.Clean(l)]
		switch {
		case sum == "":
			findings = append(findings, fmt.Sprintf("the saved tar lacks layer %s of %s", l, name))
		case sum != cfg.RootFS.DiffIDs[i] && (manifest == nil || i >= len(manifest.layers) || manifest.layers[i] != sum):
			findings = append(findings, fmt.Sprintf("the saved tar's layer %s of %s has the content of %s, which is neither layer %d of its config nor of its manifest", l, name, sum, i+1))
		}
	}
	return findings
}

// tarImage is an image manifest in a saved tar: its config and layers.
type tarImage struct {
	config string
	layers []string
}

// tarImages returns the image manifests the manifest or index with this
// digest names in a saved tar (an index: its image manifests, not the
// attestation manifests).
func tarImages(small map[string][]byte, digest string, depth int) []tarImage {
	if depth > 4 {
		return nil
	}
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if json.Unmarshal(small["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")], &m) != nil {
		return nil
	}
	if m.Config.Digest != "" {
		t := tarImage{config: m.Config.Digest}
		for _, l := range m.Layers {
			t.layers = append(t.layers, l.Digest)
		}
		return []tarImage{t}
	}
	var out []tarImage
	for _, e := range m.Manifests {
		if e.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		out = append(out, tarImages(small, e.Digest, depth+1)...)
	}
	return out
}

// saveVerified saves the verified images' names to file with save, checks
// the tar and only then moves it to file.
func saveVerified(images []builtImage, file string, save func(tmp string, names []string) error) []string {
	var names []string
	for _, img := range images {
		names = append(names, img.names()...)
	}
	tmp := file + ".partial"
	defer os.Remove(tmp) //nolint:errcheck // gone after the rename
	if err := save(tmp, names); err != nil {
		return []string{"docker save: " + err.Error()}
	}
	f, err := os.Open(tmp) //nolint:gosec // the file docker save just wrote
	if err != nil {
		return []string{err.Error()}
	}
	findings := verifySavedTar(f, images)
	_ = f.Close()
	if len(findings) > 0 {
		return findings
	}
	if err := os.Rename(tmp, file); err != nil {
		return []string{err.Error()}
	}
	return nil
}

// dockerSave runs docker save -o tmp names.
func dockerSave(tmp string, names []string) error {
	args := append([]string{"save", "-o", tmp, "--"}, names...)
	out, err := exec.Command("docker", args...).CombinedOutput() //nolint:gosec // names come from the build's own metadata, after --
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// dockerImageID returns the local image ID of name.
func dockerImageID(name string) (string, error) {
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", "--", name).Output() //nolint:gosec // name comes from the build's own metadata
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// verifyDeps are verify mode's ties to Docker, replaced in tests.
type verifyDeps struct {
	inspect func(string) (string, error)
	save    func(tmp string, names []string) error
}

var realVerifyDeps = verifyDeps{inspect: dockerImageID, save: dockerSave}

// runVerify is verify mode; saveTo, when set, is -save's file.
func runVerify(saveTo string, deps verifyDeps, stdout io.Writer) int {
	meta := os.Getenv("BAKE_METADATA")
	r := &report{out: stdout}
	if strings.TrimSpace(meta) == "" {
		r.add("BAKE_METADATA", 0, "empty: set it to the bake-action step's metadata output")
		fmt.Fprintln(stdout, "check-image-pins: the built image cannot be verified.")
		return 1
	}
	findings, images, ids := verifyBuilt([]byte(meta), deps.inspect)
	for _, f := range findings {
		r.add("BAKE_METADATA", 0, f)
	}
	if r.bad > 0 {
		fmt.Fprintf(stdout, "check-image-pins: %d finding(s): the local images are not the checked build.\n", r.bad)
		return 1
	}
	n := 0
	for _, img := range images {
		n += len(img.names())
	}
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		if len(ids) != 1 || !imageID.MatchString(ids[0]) {
			fmt.Fprintf(stdout, "check-image-pins: %d distinct image IDs; no image output.\n", len(ids))
		} else if err := appendLine(out, "image="+ids[0]); err != nil {
			r.add("GITHUB_OUTPUT", 0, err.Error())
			return 1
		}
	}
	if saveTo != "" {
		for _, f := range saveVerified(images, saveTo, deps.save) {
			r.add(saveTo, 0, f)
		}
		if r.bad > 0 {
			fmt.Fprintf(stdout, "check-image-pins: %d finding(s) in the saved images; nothing saved.\n", r.bad)
			return 1
		}
		fmt.Fprintf(stdout, "check-image-pins: %d image name(s) are the checked build's output (%s), saved to %s and checked there.\n", n, strings.Join(ids, ", "), saveTo)
		return 0
	}
	fmt.Fprintf(stdout, "check-image-pins: %d image name(s) are the checked build's output (%s).\n", n, strings.Join(ids, ", "))
	return 0
}

// appendLine appends one line to file (a GitHub Actions command file).
func appendLine(file, line string) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // the runner's own GITHUB_OUTPUT file
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, line); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
