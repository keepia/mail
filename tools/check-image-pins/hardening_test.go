package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestBuildCommands: the build forms of #46 point 1 (review A delta 3,
// finding 1) are found, and commands that only run images are not.
func TestBuildCommands(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"docker build .", []string{"docker build"}},
		{"docker buildx --builder b build .", []string{"buildx build"}},
		{"docker buildx --builder=b bake", []string{"buildx bake"}},
		{"docker --context x build .", []string{"docker build"}},
		{"docker -H unix:///x.sock --debug image build .", []string{"docker image build"}},
		{"docker --tlsverify --unknown v builder build .", []string{"docker builder build"}},
		{"docker compose build", []string{"docker compose build"}},
		{"docker compose -f c.yml -p x up --build -d", []string{"docker compose up --build"}},
		{"docker compose run --build --rm a true", []string{"docker compose run --build"}},
		{"docker compose watch", []string{"docker compose watch"}},
		{"docker-compose build a", []string{"docker-compose build"}},
		{"podman-compose up --build", []string{"podman-compose up --build"}},
		{"nerdctl build .", []string{"nerdctl build"}},
		{"nerdctl --namespace k8s.io build .", []string{"nerdctl build"}},
		{"nerdctl compose build", []string{"nerdctl compose build"}},
		{"podman build .", []string{"podman build"}},
		{"buildah bud .", []string{"buildah build"}},
		{`subprocess.run(["docker", "build", "."])`, []string{"docker build"}},
		{`execFileSync('docker', ['compose', 'up', '--build'])`, []string{"docker compose up --build"}},
		{"sudo /usr/bin/docker build .", []string{"docker build"}},
		{"docker compose up --no-build -d", nil},
		{"docker compose up --no-build -d && echo --build", nil},
		{"docker --context x run --rm busybox build", nil},
		{"docker -D run --rm busybox build", nil},
		{"docker compose run --no-build --rm a build", nil},
		{"docker image inspect a", nil},
	}
	for _, c := range cases {
		got := buildCommands(c.text)
		if !slices.Equal(got, c.want) {
			t.Errorf("buildCommands(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// TestCheckMakefileEnv: a Makefile line that sets PATH or HOME, or names
// DOCKER_CONFIG, DOCKER_HOST or DOCKER_CONTEXT, is reported (#46 point
// 6); reading PATH, and other names that end in PATH, are not.
func TestCheckMakefileEnv(t *testing.T) {
	cases := map[string]bool{
		"export PATH := $(CURDIR)/evil:$(PATH)": true,
		"PATH += :x":                            true,
		"images: PATH = x":                      true,
		"override HOME := x":                    true,
		"export HOME":                           true,
		"\tenv PATH=x go run ./tools/x":         true,
		"export DOCKER_HOST":                    true,
		"X := $(DOCKER_CONFIG)":                 true,
		"DOCKER_CONTEXT ?= x":                   true,
		"GOPATH := x":                           false,
		"SECRETS_PATH := x":                     false,
		"\t@echo $(PATH) $$HOME":                false,
		"X := $(PATH)":                          false,
		"export GOFLAGS := -mod=mod":            true,
	}
	for line, want := range cases {
		got := len(CheckMakefile([]byte(line+"\n"))) > 0
		if got != want {
			t.Errorf("CheckMakefile(%q) reported %v, want %v", line, got, want)
		}
	}
}

// fakeImage is a docker save layout of one image: its blobs, the digest
// of its index (the containerd store's image ID) and of its config (the
// classic store's image ID).
type fakeImage struct {
	blobs          map[string][]byte
	index, config  string
	layer          string
	manifestDigest string
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newFakeImage builds an image whose content depends on v, with an
// attestation manifest in its index, as BuildKit makes them.
func newFakeImage(t *testing.T, v string) fakeImage {
	t.Helper()
	img := fakeImage{blobs: map[string][]byte{}}
	add := func(b []byte) string {
		d := digestOf(b)
		img.blobs[d] = b
		return d
	}
	img.layer = add([]byte("layer " + v))
	img.config = add(mustJSON(t, map[string]any{"v": v, "rootfs": map[string]any{"diff_ids": []string{img.layer}}}))
	img.manifestDigest = add(mustJSON(t, map[string]any{"config": map[string]string{"digest": img.config}, "layers": []map[string]string{{"digest": img.layer}}}))
	attConfig := add([]byte("attestation config " + v))
	att := add(mustJSON(t, map[string]any{"config": map[string]string{"digest": attConfig}}))
	img.index = add(mustJSON(t, map[string]any{"manifests": []map[string]any{
		{"digest": img.manifestDigest},
		{"digest": att, "annotations": map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
	}}))
	return img
}

// saveTar writes a docker save tar that names img as name. indexImg, when
// set, is what index.json names instead (an inconsistent tar).
func saveTar(t *testing.T, name string, img fakeImage, indexImg *fakeImage, tamper bool) []byte {
	t.Helper()
	if indexImg == nil {
		indexImg = &img
	}
	files := map[string][]byte{}
	for _, im := range []fakeImage{img, *indexImg} {
		for d, b := range im.blobs {
			files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")] = b
		}
	}
	if tamper {
		files["blobs/sha256/"+strings.TrimPrefix(img.layer, "sha256:")] = []byte("other layer")
	}
	files["manifest.json"] = mustJSON(t, []map[string]any{{
		"Config":   "blobs/sha256/" + strings.TrimPrefix(img.config, "sha256:"),
		"RepoTags": []string{familiarName(name)},
		"Layers":   []string{"blobs/sha256/" + strings.TrimPrefix(img.layer, "sha256:")},
	}})
	files["index.json"] = mustJSON(t, map[string]any{"manifests": []map[string]any{{
		"digest":      indexImg.index,
		"annotations": map[string]string{"io.containerd.image.name": name},
	}}})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o444, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestVerifySavedTar: the tar -save writes must hold the checked build's
// output under every name (#46 point 4, review B delta 3 N1): a re-tag
// between verify and save, an inconsistent tar or a changed blob fails.
func TestVerifySavedTar(t *testing.T) {
	const name = "ghcr.io/keepia/mail-postfix:dev"
	a, b := newFakeImage(t, "a"), newFakeImage(t, "b")
	classic := builtImage{Name: name, Digest: "sha256:" + strings.Repeat("9", 64), ConfigDigest: a.config}
	containerd := builtImage{Name: name, Digest: a.index}
	cases := []struct {
		name string
		meta builtImage
		tar  []byte
		want string
	}{
		{"classic store", classic, saveTar(t, name, a, nil, false), ""},
		{"containerd store", containerd, saveTar(t, name, a, nil, false), ""},
		{"Docker Hub name", builtImage{Name: "docker.io/library/x:dev", Digest: a.index}, saveTar(t, "docker.io/library/x:dev", a, nil, false), ""},
		{"re-tagged, classic", classic, saveTar(t, name, b, nil, false), "which is not the checked build's output"},
		{"re-tagged, containerd", containerd, saveTar(t, name, b, nil, false), "which is not the checked build's output"},
		{"index and manifest.json disagree", containerd, saveTar(t, name, b, &a, false), "does not name the config manifest.json names"},
		{"changed layer", classic, saveTar(t, name, a, nil, true), "has the content of"},
		{"other name", classic, saveTar(t, "ghcr.io/keepia/other:dev", a, nil, false), "has no image named " + name},
		{"not a tar", classic, []byte("nope"), "does not read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := verifySavedTar(bytes.NewReader(c.tar), []builtImage{c.meta})
			if c.want == "" && len(got) > 0 || c.want != "" && !strings.Contains(strings.Join(got, "\n"), c.want) {
				t.Fatalf("findings %q, want %q", got, c.want)
			}
		})
	}
}

// TestVerifySave: -verify-built -save writes the tar only when it holds
// the verified image, and puts out the verified image ID for the test
// step; a re-tag between the inspect and the save leaves no file.
func TestVerifySave(t *testing.T) {
	const name = "ghcr.io/keepia/mail-postfix:dev"
	a, b := newFakeImage(t, "a"), newFakeImage(t, "b")
	t.Setenv("BAKE_METADATA", string(mustJSON(t, map[string]any{
		"postfix": map[string]string{"image.name": name, "containerimage.digest": a.index},
	})))
	inspect := func(string) (string, error) { return a.index, nil }
	for _, c := range []struct {
		name  string
		saved fakeImage
		code  int
	}{
		{"verified image", a, 0},
		{"re-tagged after verify", b, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "github-output")
			if err := os.WriteFile(out, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GITHUB_OUTPUT", out)
			file := filepath.Join(dir, "image.tar")
			save := func(tmp string, names []string) error {
				if !slices.Equal(names, []string{name}) {
					t.Errorf("saved names %q, want %q", names, name)
				}
				return os.WriteFile(tmp, saveTar(t, name, c.saved, nil, false), 0o600)
			}
			var stdout bytes.Buffer
			code := runVerify(file, verifyDeps{inspect: inspect, save: save}, &stdout)
			_, statErr := os.Stat(file)
			entries, _ := os.ReadDir(dir)
			output, _ := os.ReadFile(out)
			switch {
			case code != c.code:
				t.Fatalf("exit %d, want %d:\n%s", code, c.code, stdout.String())
			case c.code == 0 && statErr != nil:
				t.Fatalf("no saved tar: %v", statErr)
			case c.code != 0 && len(entries) != 1:
				t.Fatalf("files left after a failed save: %v", entries)
			case string(output) != "image="+a.index+"\n":
				t.Fatalf("GITHUB_OUTPUT %q, want image=%s", output, a.index)
			}
		})
	}
}

// TestBakeLocalResolvesDockerOnce: local mode looks the docker CLI up once
// and runs that absolute path for the resolve and the build (#46 point
// 6), so a PATH that changes after the plan cannot swap the binary.
func TestBakeLocalResolvesDockerOnce(t *testing.T) {
	if !haveBuildx(t) {
		t.Skip("docker buildx is not available")
	}
	bin, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join("testdata", "repos", "pass-bake")
	var out, errOut bytes.Buffer
	if code := run([]string{"-bake-local", "-root", repo, "-dry-run"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "running "+abs+" buildx bake") {
		t.Fatalf("exit %d, want 0 with the absolute docker path %s:\n%s%s", code, abs, out.String(), errOut.String())
	}
	p := planLocal(repo, localOptions{})
	if len(p.problem) > 0 {
		t.Fatalf("plan: %q", p.problem)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := p.b.print(nil, p.names); err != nil {
		t.Fatalf("resolve after PATH changed: %v", err)
	}
}
