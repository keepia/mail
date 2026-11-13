package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// ociImage is a pushed row as BuildKit writes it with an attestation: an
// index with one platform manifest and one attestation manifest.
type ociImage struct {
	blobs                           map[string][]byte
	index, manifest, config, attest string
	indexJSON                       []byte
	attestRef                       string
}

const ociIndexType = "application/vnd.oci.image.index.v1+json"

func addBlob(blobs map[string][]byte, b []byte) string {
	d := digestOf(b)
	blobs[d] = b
	return d
}

// newOCIImage builds a row for linux/<arch>; edit changes the index's
// manifests before it is stored (nil: the normal shape).
func newOCIImage(t *testing.T, arch, seed string, edit func(m []map[string]any) []map[string]any) ociImage {
	t.Helper()
	img := ociImage{blobs: map[string][]byte{}}
	layer := addBlob(img.blobs, []byte("layer "+seed))
	img.config = addBlob(img.blobs, mustJSON(t, map[string]any{
		"os": "linux", "architecture": arch, "config": map[string]any{"Labels": map[string]string{versionKey: "0.1.0"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{layer}},
	}))
	img.manifest = addBlob(img.blobs, mustJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"digest": img.config}, "layers": []map[string]any{{"digest": layer}},
	}))
	statement := addBlob(img.blobs, []byte("provenance "+seed))
	img.attest = addBlob(img.blobs, mustJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"digest": statement}, "layers": []map[string]any{{"digest": statement}},
	}))
	img.attestRef = img.manifest
	manifests := []map[string]any{
		{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": img.manifest, "platform": map[string]string{"os": "linux", "architecture": arch}},
		{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": img.attest, "platform": map[string]string{"os": "unknown", "architecture": "unknown"},
			"annotations": map[string]string{refTypeKey: attestationType, refDigestKey: img.manifest}},
	}
	if edit != nil {
		manifests = edit(manifests)
	}
	img.indexJSON = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": ociIndexType, "manifests": manifests})
	img.index = addBlob(img.blobs, img.indexJSON)
	return img
}

// ociTar writes img as an OCI layout tar; tamper replaces one blob's
// content, indexDigest what index.json names.
func ociTar(t *testing.T, img ociImage, indexDigest string, tamper string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	put("index.json", mustJSON(t, map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"mediaType": ociIndexType, "digest": indexDigest}}}))
	for _, d := range sortedKeysBytes(img.blobs) {
		b := img.blobs[d]
		if d == tamper {
			b = []byte("tampered")
		}
		put("blobs/sha256/"+strings.TrimPrefix(d, "sha256:"), b)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sortedKeysBytes(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func rowMeta(t *testing.T, target, name, digest, config string) []byte {
	t.Helper()
	m := map[string]string{"image.name": name, "containerimage.digest": digest}
	if config != "" {
		m["containerimage.config.digest"] = config
	}
	return mustJSON(t, map[string]any{"buildx.build.warnings": []any{}, target: m})
}

// The names in the two metadata files (#75): the build row's tested image
// and the push step's bare repository as buildx reports it.
const (
	testedName    = "ghcr.io/keepia/mail-postfix:0.1.0"
	pushName      = "ghcr.io/keepia/mail-postfix:latest"
	rehearsalName = "localhost:5000/keepia/mail-postfix:latest"
)

// regOf is a registry that holds the given rows of repo, as BuildKit
// pushed them: each index and every blob by digest.
func regOf(t *testing.T, repo string, imgs ...ociImage) *fakeRegistry {
	t.Helper()
	reg := newFakeRegistry(t)
	for _, img := range imgs {
		for d, b := range img.blobs {
			reg.refs[repo+"@"+d] = b
		}
	}
	return reg
}

// TestVerifyPushed is test 22: the pushed image must be the tested one.
func TestVerifyPushed(t *testing.T) {
	const name = testedName
	img := newOCIImage(t, "amd64", "a", nil)
	other := newOCIImage(t, "amd64", "b", nil)
	second := newOCIImage(t, "amd64", "c", func(m []map[string]any) []map[string]any {
		return append(m, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": other.manifest, "platform": map[string]string{"os": "linux", "architecture": "arm64"}})
	})
	for d, b := range other.blobs {
		second.blobs[d] = b
	}
	strayAttest := newOCIImage(t, "amd64", "d", func(m []map[string]any) []map[string]any {
		m[1]["annotations"] = map[string]string{refTypeKey: attestationType, refDigestKey: other.manifest}
		return m
	})
	armOnly := newOCIImage(t, "arm64", "e", nil)
	tested := rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), img.config)
	pushed := func(n, digest string) []byte { return rowMeta(t, "postfix", n, digest, "") }
	const rehearsalRepo = "localhost:5000/keepia/mail-postfix"
	cases := []struct {
		name         string
		tarData      []byte
		meta, tested []byte
		target       string
		want         string
		repo         string // the repository of the success record
	}{
		{"tested image, pushed to GHCR", ociTar(t, img, img.index, ""), pushed(pushName, img.index), tested, "postfix", "", testRepo},
		// #75: the rehearsal's own registry.
		{"tested image, pushed to the rehearsal's registry", ociTar(t, img, img.index, ""), pushed(rehearsalName, img.index), tested, "postfix", "", rehearsalRepo},
		{"changed blob", ociTar(t, img, img.index, img.config), pushed(pushName, img.index), tested, "postfix", "has the content of", ""},
		{"index digest is not the metadata's", ociTar(t, img, img.index, ""), pushed(pushName, other.index), tested, "postfix", "want exactly the pushed index", ""},
		{"second platform manifest", ociTar(t, second, second.index, ""), pushed(pushName, second.index), rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), second.config), "postfix", "holds 2 image manifests", ""},
		{"attestation of another manifest", ociTar(t, strayAttest, strayAttest.index, ""), pushed(pushName, strayAttest.index), rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), strayAttest.config), "postfix", "references " + other.manifest, ""},
		{"config is not the tested one", ociTar(t, other, other.index, ""), pushed(pushName, other.index), tested, "postfix", "but the tested config is " + img.config, ""},
		{"wrong platform", ociTar(t, armOnly, armOnly.index, ""), pushed(pushName, armOnly.index), rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), armOnly.config), "postfix", "is not linux/amd64", ""},
		{"tested metadata without config digest", ociTar(t, img, img.index, ""), pushed(pushName, img.index), rowMeta(t, "postfix", name, img.index, ""), "postfix", "has no containerimage.config.digest", ""},
		{"push metadata names another config", ociTar(t, img, img.index, ""), rowMeta(t, "postfix", pushName, img.index, other.config), tested, "postfix", "names the config " + other.config, ""},
		{"tested metadata of another repository", ociTar(t, img, img.index, ""), pushed(pushName, img.index), rowMeta(t, "postfix", "ghcr.io/other/mail-postfix:0.1.0", img.index, img.config), "postfix", "want " + name, ""},
		// #75 (D5): the push step's metadata names exactly <R>/<repo>:latest.
		{"push metadata names the tested tag", ociTar(t, img, img.index, ""), pushed(testedName, img.index), tested, "postfix", "names the images [" + testedName + "], want exactly one of " + pushName + " or " + rehearsalName, ""},
		{"push metadata of another registry", ociTar(t, img, img.index, ""), pushed("ghcr.io/other/mail-postfix:latest", img.index), tested, "postfix", "want exactly one of", ""},
		{"push metadata of another image", ociTar(t, img, img.index, ""), pushed("localhost:5000/keepia/mail-olefy:latest", img.index), tested, "postfix", "want exactly one of", ""},
		{"push metadata with a second name", ociTar(t, img, img.index, ""), pushed(pushName+","+rehearsalName, img.index), tested, "postfix", "want exactly one of", ""},
		{"push metadata with no name", ociTar(t, img, img.index, ""), pushed("", img.index), tested, "postfix", "names the images [], want exactly one of", ""},
		{"another target", ociTar(t, img, img.index, ""), rowMeta(t, "olefy", pushName, img.index, ""), tested, "postfix", "want exactly postfix", ""},
		{"not a tar", []byte("nope"), pushed(pushName, img.index), tested, "postfix", "does not read", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), pushedTar)
			if err := os.WriteFile(p, c.tarData, 0o600); err != nil {
				t.Fatal(err)
			}
			repo := testRepo
			if strings.Contains(string(c.meta), "localhost:5000") {
				repo = rehearsalRepo
			}
			reg := regOf(t, repo, img, other, second, strayAttest, armOnly)
			rec, findings := verifyPushed(pushedInput{meta: c.meta, tested: c.tested, target: c.target, platform: "linux/amd64", version: "0.1.0", tar: p, reg: reg})
			got := strings.Join(findings, "\n")
			if c.want == "" {
				if len(findings) > 0 || rec.Config != img.config || rec.Index != img.index || rec.Manifest != img.manifest || rec.Repository != c.repo {
					t.Fatalf("findings %q, record %+v", findings, rec)
				}
				// The registry read: the index and its platform manifest,
				// in the repository the row was pushed to.
				if want := []string{"raw " + c.repo + "@" + img.index, "raw " + c.repo + "@" + img.manifest}; !slices.Equal(reg.calls, want) {
					t.Fatalf("registry calls %q, want %q", reg.calls, want)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("findings %q, want %q", findings, c.want)
			}
			// No registry call when a check of the metadata or the tar
			// failed.
			if len(reg.calls) > 0 {
				t.Fatalf("refused before the registry read, but the registry was asked: %q", reg.calls)
			}
		})
	}
}

// TestVerifyPushedRegistryRead (#75, D3 and D-e): after every check of
// pushed.tar passed, -verify-pushed reads the row back from the registry
// it was pushed to; other content there is a mismatch, a failed read is
// reported apart from it.
func TestVerifyPushedRegistryRead(t *testing.T) {
	img := newOCIImage(t, "amd64", "a", nil)
	other := newOCIImage(t, "amd64", "b", nil)
	data := ociTar(t, img, img.index, "")
	const mismatch = "the registry holds other content than pushed.tar for " + testRepo + "@"
	cases := []struct {
		name string
		edit func(reg *fakeRegistry)
		want string
	}{
		{"index missing", func(reg *fakeRegistry) { delete(reg.refs, testRepo+"@"+img.index) }, registryReadPrefix + ": " + testRepo + "@" + img.index + ": not found"},
		{"index bytes differ", func(reg *fakeRegistry) { reg.refs[testRepo+"@"+img.index] = other.indexJSON }, mismatch + img.index + ": " + testRepo + "@" + img.index + " has the content of " + other.index},
		{"platform manifest differs", func(reg *fakeRegistry) { reg.refs[testRepo+"@"+img.manifest] = other.blobs[other.manifest] }, mismatch + img.index + ": " + testRepo + "@" + img.manifest + " has the content of " + other.manifest},
		{"platform manifest missing", func(reg *fakeRegistry) { delete(reg.refs, testRepo+"@"+img.manifest) }, registryReadPrefix + ": " + testRepo + "@" + img.manifest},
		{"registry error", func(reg *fakeRegistry) { reg.errs[testRepo+"@"+img.index] = errors.New("unauthorized") }, registryReadPrefix + ": " + testRepo + "@" + img.index + ": unauthorized. pushed.tar passed every check, so pushed.tar is the tested image; what the registry holds for this row is unknown, because the read failed. This is a read error, not a content mismatch"},
		{"another repository holds it", func(reg *fakeRegistry) {
			moved := map[string][]byte{}
			for k, v := range reg.refs {
				moved[strings.Replace(k, testRepo, "localhost:5000/keepia/mail-postfix", 1)] = v
			}
			reg.refs = moved
		}, registryReadPrefix + ": " + testRepo + "@" + img.index + ": not found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), pushedTar)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
			reg := regOf(t, testRepo, img, other)
			c.edit(reg)
			rec, f := verifyPushed(pushedInput{meta: rowMeta(t, "postfix", pushName, img.index, ""), tested: rowMeta(t, "postfix", testedName, img.index, img.config),
				target: "postfix", platform: "linux/amd64", version: "0.1.0", tar: p, reg: reg})
			if len(f) != 1 || !strings.Contains(f[0], c.want) || rec.Index != "" {
				t.Fatalf("findings %q, record %+v, want one finding with %q", f, rec, c.want)
			}
			if isRead := strings.HasPrefix(f[0], registryReadPrefix); isRead != strings.HasPrefix(c.want, registryReadPrefix) {
				t.Fatalf("finding %q: read error %v, want %v", f[0], isRead, !isRead)
			}
		})
	}
}

// TestVerifyPushedOpensOnlyARegularFile: pushed.tar is a directory, a
// symlink, or swapped for a FIFO between the Lstat and the open
// (revision 5): each is refused.
func TestVerifyPushedOpensOnlyARegularFile(t *testing.T) {
	img := newOCIImage(t, "amd64", "a", nil)
	data := ociTar(t, img, img.index, "")
	in := func(p string) pushedInput {
		return pushedInput{meta: rowMeta(t, "postfix", pushName, img.index, ""), tested: rowMeta(t, "postfix", testedName, img.index, img.config),
			target: "postfix", platform: "linux/amd64", version: "0.1.0", tar: p, reg: regOf(t, testRepo, img)}
	}
	t.Run("directory", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), pushedTar)
		if err := os.Mkdir(p, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, f := verifyPushed(in(p)); len(f) != 1 || !strings.Contains(f[0], "is not a regular file") {
			t.Fatalf("findings %q", f)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real.tar")
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, pushedTar)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		if _, f := verifyPushed(in(p)); len(f) != 1 || !strings.Contains(f[0], "is not a regular file") {
			t.Fatalf("findings %q", f)
		}
	})
	t.Run("symlink after Lstat", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, pushedTar)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		i := in(p)
		i.afterLstat = func() {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "x"), p); err != nil {
				t.Fatal(err)
			}
		}
		if _, f := verifyPushed(i); len(f) != 1 || !strings.Contains(f[0], "open") {
			t.Fatalf("findings %q, want the O_NOFOLLOW open to fail", f)
		}
	})
	t.Run("FIFO after Lstat", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), pushedTar)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		i := in(p)
		i.afterLstat = func() {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, f := verifyPushed(i); len(f) != 1 || !strings.Contains(f[0], "changed between Lstat and open") {
			t.Fatalf("findings %q, want the fstat check to refuse the FIFO", f)
		}
	})
}

// TestRunVerifyPushed: the mode reads pushed.tar in the working
// directory and the tested metadata from $RUNNER_TEMP/tested, and writes
// the digest file and the step outputs only on success.
// useRegistry makes -verify-pushed read from reg for the rest of the test.
func useRegistry(t *testing.T, reg registry) {
	t.Helper()
	old := pushedRegistry
	pushedRegistry = func() (registry, error) { return reg, nil }
	t.Cleanup(func() { pushedRegistry = old })
}

// verifyPushedEnv prepares a push row of img in the rehearsal's registry
// for run -verify-pushed and returns RUNNER_TEMP.
func verifyPushedEnv(t *testing.T, img ociImage) string {
	t.Helper()
	work, temp := t.TempDir(), t.TempDir()
	t.Chdir(work)
	if err := os.WriteFile(pushedTar, ociTar(t, img, img.index, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(temp, "tested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temp, "tested", "metadata.json"), rowMeta(t, "postfix", testedName, img.index, img.config), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(temp, "github-output")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNNER_TEMP", temp)
	t.Setenv("GITHUB_OUTPUT", out)
	t.Setenv("BAKE_TARGET", "postfix")
	t.Setenv("PLATFORM", "linux/amd64")
	t.Setenv("VERSION", "0.1.0")
	t.Setenv("BAKE_METADATA", string(rowMeta(t, "postfix", rehearsalName, img.index, "")))
	return temp
}

// TestRunVerifyPushedReadError (#75, D-e): a failed registry read after
// every tar check passed exits 1 with its own summary, and writes no
// digest file.
func TestRunVerifyPushedReadError(t *testing.T) {
	img := newOCIImage(t, "amd64", "a", nil)
	temp := verifyPushedEnv(t, img)
	reg := newFakeRegistry(t)
	reg.errs["localhost:5000/keepia/mail-postfix@"+img.index] = errors.New("dial tcp 127.0.0.1:5000: connect: connection refused")
	useRegistry(t, reg)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-verify-pushed"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1:\n%s%s", code, stdout.String(), stderr.String())
	}
	// #51 item 17: pushed.tar is the tested image, and what the registry
	// holds is unknown; the old text claimed more ("it is the tested
	// image", read as the registry's content).
	s := stdout.String()
	for _, want := range []string{
		"connection refused. pushed.tar passed every check, so pushed.tar is the tested image;",
		"what the registry holds for this row is unknown, because the read failed.",
		"a read error, not a mismatch.",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "is not the tested image") || strings.Contains(s, "(it is the tested image)") {
		t.Fatalf("output:\n%s", s)
	}
	if _, err := os.Stat(filepath.Join(temp, "digest")); !os.IsNotExist(err) {
		t.Fatalf("a digest directory after a failed read: %v", err)
	}
}

// TestRunVerifyPushedMismatch (#51 item 19): other content in the
// registry after every tar check passed exits 1 with the mismatch
// summary, not the read-error one, and writes no digest file.
func TestRunVerifyPushedMismatch(t *testing.T) {
	img := newOCIImage(t, "amd64", "a", nil)
	other := newOCIImage(t, "amd64", "b", nil)
	temp := verifyPushedEnv(t, img)
	const repo = "localhost:5000/keepia/mail-postfix"
	reg := regOf(t, repo, img)
	reg.refs[repo+"@"+img.index] = other.indexJSON
	useRegistry(t, reg)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-verify-pushed"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1:\n%s%s", code, stdout.String(), stderr.String())
	}
	s := stdout.String()
	if !strings.Contains(s, "the registry holds other content than pushed.tar for "+repo+"@"+img.index) ||
		!strings.Contains(s, "check-image-pins: 1 finding(s): the pushed image is not the tested image.\n") ||
		strings.Contains(s, "read error") {
		t.Fatalf("output:\n%s", s)
	}
	if _, err := os.Stat(filepath.Join(temp, "digest")); !os.IsNotExist(err) {
		t.Fatalf("a digest directory after a mismatch: %v", err)
	}
}

// TestRunVerifyPushedCannotStart (#51 item 18): each failure before the
// comparison (no RUNNER_TEMP, no tested metadata, no registry client)
// exits 1 with one summary line saying that nothing was compared.
func TestRunVerifyPushedCannotStart(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, temp string)
		want  string
	}{
		{"no RUNNER_TEMP", func(t *testing.T, _ string) { t.Setenv("RUNNER_TEMP", "") }, "RUNNER_TEMP: empty: verify-pushed runs in a release.yml push job"},
		{"no tested metadata", func(t *testing.T, temp string) {
			if err := os.Remove(filepath.Join(temp, "tested", "metadata.json")); err != nil {
				t.Fatal(err)
			}
		}, "tested metadata: open "},
		{"no registry client", func(t *testing.T, _ string) {
			old := pushedRegistry
			pushedRegistry = func() (registry, error) { return nil, errors.New("cannot find the docker CLI") }
			t.Cleanup(func() { pushedRegistry = old })
		}, "registry client: cannot find the docker CLI"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := newOCIImage(t, "amd64", "a", nil)
			temp := verifyPushedEnv(t, img)
			useRegistry(t, regOf(t, "localhost:5000/keepia/mail-postfix", img))
			c.setup(t, temp)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-verify-pushed"}, &stdout, &stderr); code != 1 {
				t.Fatalf("exit %d, want 1:\n%s%s", code, stdout.String(), stderr.String())
			}
			s := stdout.String()
			summary := "check-image-pins: verify-pushed could not start: " + c.want
			if !strings.Contains(s, summary) || !strings.HasSuffix(s, "; nothing was compared.\n") || strings.Count(s, "check-image-pins: ") != 1 {
				t.Fatalf("output lacks one summary %q … \"; nothing was compared.\":\n%s", summary, s)
			}
			if _, err := os.Stat(filepath.Join(temp, "digest")); !os.IsNotExist(err) {
				t.Fatalf("a digest directory: %v", err)
			}
		})
	}
}

func TestRunVerifyPushed(t *testing.T) {
	img := newOCIImage(t, "amd64", "a", nil)
	temp := verifyPushedEnv(t, img)
	out := os.Getenv("GITHUB_OUTPUT")
	useRegistry(t, regOf(t, "localhost:5000/keepia/mail-postfix", img))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-verify-pushed"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	// The success line names the registry the row was read back from.
	if want := "for localhost:5000/keepia/mail-postfix linux/amd64: index " + img.index + ", manifest " + img.manifest + "; read back from the registry localhost:5000.\n"; !strings.Contains(stdout.String(), want) {
		t.Fatalf("output lacks %q:\n%s", want, stdout.String())
	}
	b, err := os.ReadFile(filepath.Join(temp, "digest", "postfix-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec pushedRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.Index != img.index || rec.Config != img.config || rec.Version != "0.1.0" || rec.Repository != "localhost:5000/keepia/mail-postfix" {
		t.Fatalf("digest file %s (%v)", b, err)
	}
	o, _ := os.ReadFile(out)
	if string(o) != "index="+img.index+"\nmanifest="+img.manifest+"\n" {
		t.Fatalf("GITHUB_OUTPUT %q", o)
	}
	// A second run finds the digest file and refuses to overwrite it.
	if code := run([]string{"-verify-pushed"}, &stdout, &stderr); code != 1 {
		t.Fatalf("second run: exit %d, want 1", code)
	}
	// No other flag or argument (no tag name).
	for _, args := range [][]string{{"-verify-pushed", "x"}, {"-verify-pushed", "-publish-index"}, {"-move-latest", "-tag", "0.1"}, {"-publish-index", "-tag", "0.1"}, {"-move-latest", "-build", "x"}} {
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit %d, want 2 (usage)", args, code)
		}
	}
}
