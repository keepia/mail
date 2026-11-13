package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

// TestVerifyPushed is test 22: the pushed image must be the tested one.
func TestVerifyPushed(t *testing.T) {
	const name = "ghcr.io/keepia/mail-postfix:0.1.0"
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
	cases := []struct {
		name         string
		tarData      []byte
		meta, tested []byte
		target       string
		want         string
	}{
		{"tested image", ociTar(t, img, img.index, ""), rowMeta(t, "postfix", name, img.index, ""), tested, "postfix", ""},
		{"changed blob", ociTar(t, img, img.index, img.config), rowMeta(t, "postfix", name, img.index, ""), tested, "postfix", "has the content of"},
		{"index digest is not the metadata's", ociTar(t, img, img.index, ""), rowMeta(t, "postfix", name, other.index, ""), tested, "postfix", "want exactly the pushed index"},
		{"second platform manifest", ociTar(t, second, second.index, ""), rowMeta(t, "postfix", name, second.index, ""), rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), second.config), "postfix", "holds 2 image manifests"},
		{"attestation of another manifest", ociTar(t, strayAttest, strayAttest.index, ""), rowMeta(t, "postfix", name, strayAttest.index, ""), rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), strayAttest.config), "postfix", "references " + other.manifest},
		{"config is not the tested one", ociTar(t, other, other.index, ""), rowMeta(t, "postfix", name, other.index, ""), tested, "postfix", "but the tested config is " + img.config},
		{"wrong platform", ociTar(t, armOnly, armOnly.index, ""), rowMeta(t, "postfix", name, armOnly.index, ""), rowMeta(t, "postfix", name, "sha256:"+strings.Repeat("9", 64), armOnly.config), "postfix", "is not linux/amd64"},
		{"tested metadata without config digest", ociTar(t, img, img.index, ""), rowMeta(t, "postfix", name, img.index, ""), rowMeta(t, "postfix", name, img.index, ""), "postfix", "has no containerimage.config.digest"},
		{"push metadata names another config", ociTar(t, img, img.index, ""), rowMeta(t, "postfix", name, img.index, other.config), tested, "postfix", "names the config " + other.config},
		{"another repository", ociTar(t, img, img.index, ""), rowMeta(t, "postfix", "ghcr.io/other/mail-postfix:0.1.0", img.index, ""), tested, "postfix", "want " + name},
		{"another target", ociTar(t, img, img.index, ""), rowMeta(t, "olefy", name, img.index, ""), tested, "postfix", "want exactly postfix"},
		{"not a tar", []byte("nope"), rowMeta(t, "postfix", name, img.index, ""), tested, "postfix", "does not read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), pushedTar)
			if err := os.WriteFile(p, c.tarData, 0o600); err != nil {
				t.Fatal(err)
			}
			rec, findings := verifyPushed(pushedInput{meta: c.meta, tested: c.tested, target: c.target, platform: "linux/amd64", version: "0.1.0", tar: p})
			got := strings.Join(findings, "\n")
			if c.want == "" {
				if len(findings) > 0 || rec.Config != img.config || rec.Index != img.index || rec.Manifest != img.manifest || rec.Repository != "ghcr.io/keepia/mail-postfix" {
					t.Fatalf("findings %q, record %+v", findings, rec)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("findings %q, want %q", findings, c.want)
			}
		})
	}
}

// TestVerifyPushedOpensOnlyARegularFile: pushed.tar is a directory, a
// symlink, or swapped for a FIFO between the Lstat and the open
// (revision 5): each is refused.
func TestVerifyPushedOpensOnlyARegularFile(t *testing.T) {
	const name = "ghcr.io/keepia/mail-postfix:0.1.0"
	img := newOCIImage(t, "amd64", "a", nil)
	data := ociTar(t, img, img.index, "")
	in := func(p string) pushedInput {
		return pushedInput{meta: rowMeta(t, "postfix", name, img.index, ""), tested: rowMeta(t, "postfix", name, img.index, img.config),
			target: "postfix", platform: "linux/amd64", version: "0.1.0", tar: p}
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
func TestRunVerifyPushed(t *testing.T) {
	const name = "ghcr.io/keepia/mail-postfix:0.1.0"
	img := newOCIImage(t, "amd64", "a", nil)
	work, temp := t.TempDir(), t.TempDir()
	t.Chdir(work)
	if err := os.WriteFile(pushedTar, ociTar(t, img, img.index, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(temp, "tested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temp, "tested", "metadata.json"), rowMeta(t, "postfix", name, img.index, img.config), 0o600); err != nil {
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
	t.Setenv("BAKE_METADATA", string(rowMeta(t, "postfix", name, img.index, "")))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-verify-pushed"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(temp, "digest", "postfix-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec pushedRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.Index != img.index || rec.Config != img.config || rec.Version != "0.1.0" {
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
