package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The #49 tests that use only functions f360066 already had, so the same
// file runs there as the counter-proof.

// TestBuildCommands49: lists split over lines as black and gofmt write
// them (point 3), and Compose commands that build a service without an
// image (point 2).
func TestBuildCommands49(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"subprocess.run(\n    [\n        \"docker\",\n        \"build\",\n        \".\",\n    ],\n    check=True,\n)", []string{"docker build"}},
		{"cmd := exec.Command(\n\t\"docker\",\n\t\"build\",\n\t\".\",\n)", []string{"docker build"}},
		{"await exec.exec('docker', [\n  'buildx',\n  'bake',\n])", []string{"buildx bake"}},
		{"docker compose up -d", []string{"docker compose up without --no-build"}},
		{"docker compose create", []string{"docker compose create without --no-build"}},
		{"docker compose run --rm a true", []string{"docker compose run, which builds and has no --no-build (use up -d --no-build and exec)"}},
		{"docker-compose up -d", []string{"docker-compose up without --no-build"}},
		{"docker compose up --build=true -d", []string{"docker compose up --build"}},
		{"docker compose up --no-build -d", nil},
		{"docker compose start", nil},
		{"docker compose down", nil},
	}
	for _, c := range cases {
		if got := buildCommands(c.text); !slices.Equal(got, c.want) {
			t.Errorf("buildCommands(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// TestImageUses49: the other ways an image leaves the runner (points 5
// and 9).
func TestImageUses49(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"docker compose push", []string{"compose push"}},
		{"docker-compose push postfix", []string{"compose push"}},
		{"docker buildx imagetools create -t ghcr.io/keepia/x:1 ghcr.io/keepia/x@sha256:1", []string{"buildx imagetools create"}},
		{"crane push image.tar ghcr.io/keepia/x:1", []string{"crane"}},
		{"skopeo copy docker-daemon:ghcr.io/keepia/mail-postfix:dev oci-archive:image.tar", []string{"skopeo"}},
		{"docker compose ps", nil},
	}
	for _, c := range cases {
		if got := imageUses(c.text); !slices.Equal(got, c.want) {
			t.Errorf("imageUses(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// TestCheckMakefile49: the Makefile forms of point 8 are reported; the
// repository's own forms are not. GO is compared as its whole value, not
// its first word, and any define, += or != of it is reported (#51 item 4).
func TestCheckMakefile49(t *testing.T) {
	cases := map[string]bool{
		"SHELL := ./evil-sh":                   true,
		"SHELL = /bin/bash":                    true,
		"export SHELL":                         true,
		".SHELLFLAGS := -ec":                   true,
		"include local.cfg":                    true,
		"-include $(X).mk":                     true,
		"include prototypes/x.mk":              true,
		"export GOFLAGS := -overlay=ov.json":   true,
		"GOENV = ./go.env":                     true,
		"override GOWORK := ./go.work":         true,
		"GO := ./evil/go":                      true,
		"GO := /usr/local/go/bin/go":           true,
		"GO := go -C ./evil":                   true,
		"override GO = go -C x":                true,
		"export GO := go -C x":                 true,
		"images: GO = go -C x":                 true,
		"GO += -C x":                           true,
		"GO += go":                             true,
		"GO != echo go":                        true,
		"define GO\ngo -C ./evil\nendef":       true,
		"define GO\ngo\nendef":                 true,
		"override define GO =\ngo\nendef":      true,
		"images-go:\n\t$(eval GO := go -C x)":  true,
		"\techo \"#\"; GO=./evil make images":  true,
		"# GO ?= go and an include stay":       false,
		"images-go:\n\t$(eval GO := go)":       false,
		"GO = go # the go tool":                false,
		"override GO = go":                     false,
		"export GO := go":                      false,
		"define GOPROXY_NOTE\ntext\nendef":     false,
		"export PA$(E)TH := x":                 true,
		"$(eval PA$(E)TH := x)":                true,
		"export PA$(E)TH":                      true,
		"GO ?= go":                             false,
		"include tools/lint.mk":                false,
		"\t$(GO) run ./tools/check-image-pins": false,
		"\tGOTOOLCHAIN=$$($(GO) env GOVERSION) GOBIN=$(CURDIR)/$(dir $(X)) $(GO) install x@v1": false,
		"LOCAL_BUILD_OPTIONS = $(if $(CA),-ca \"$(CA)\" -https-proxy \"$(HTTPS_PROXY)\")":      false,
		"\t$(GITLEAKS) git --log-opts=\"$$SECRETS_LOG_OPTS\" $(SECRETS_SOURCE)":                false,
	}
	for line, want := range cases {
		if got := len(CheckMakefile([]byte(line+"\n"))) > 0; got != want {
			t.Errorf("CheckMakefile(%q) reported %v, want %v", line, got, want)
		}
	}
}

// TestCheckScriptText49: a script's list split over lines is one command
// (point 3), reported at the line that opens it.
func TestCheckScriptText49(t *testing.T) {
	src := "import subprocess\n\nsubprocess.run(\n    [\n        \"docker\",\n        \"build\",\n        \".\",\n    ],\n    check=True,\n)\nprint(\"done\")\n"
	got := CheckScriptText([]byte(src))
	if len(got) != 1 || got[0].Line != 3 {
		t.Fatalf("findings %v, want one on line 3", got)
	}
}

// tarFiles writes a tar of files, in name order.
func tarFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
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

func blobPath(d string) string { return "blobs/sha256/" + strings.TrimPrefix(d, "sha256:") }

// TestVerifySavedTar49: crafted docker save tars of point 6, from reviews
// A (finding 1) and B (finding 3). Each passed f360066's check; a loader
// would then give the name another image or other layers.
func TestVerifySavedTar49(t *testing.T) {
	const name = "ghcr.io/keepia/mail-postfix:dev"
	a, b := newFakeImage(t, "a"), newFakeImage(t, "b")
	classic := builtImage{Name: name, Digest: "sha256:" + strings.Repeat("9", 64), ConfigDigest: a.config}
	// Verify requires the config digest (#27): the containerd store's
	// metadata has both digests.
	containerd := builtImage{Name: name, Digest: a.index, ConfigDigest: a.config}
	entry := func(img fakeImage, layers ...string) map[string]any {
		if layers == nil {
			layers = []string{blobPath(img.layer)}
		}
		return map[string]any{"Config": blobPath(img.config), "RepoTags": []string{name}, "Layers": layers}
	}
	build := func(manifest []map[string]any, index []string, extra map[string][]byte) []byte {
		files := map[string][]byte{}
		for _, im := range []fakeImage{a, b} {
			for d, c := range im.blobs {
				files[blobPath(d)] = c
			}
		}
		files["manifest.json"] = mustJSON(t, manifest)
		var idx []map[string]any
		for _, d := range index {
			idx = append(idx, map[string]any{"digest": d, "annotations": map[string]string{"io.containerd.image.name": name}})
		}
		files["index.json"] = mustJSON(t, map[string]any{"manifests": idx})
		for n, c := range extra {
			files[n] = c
		}
		return tarFiles(t, files)
	}
	// A compressed layer, as the containerd store saves it: the blob's
	// digest is not the config's diff_id, but it is the manifest's layer.
	gz := fakeImage{blobs: map[string][]byte{}}
	gzLayer := []byte("gzip of layer c")
	gz.layer = digestOf(gzLayer)
	gz.blobs[gz.layer] = gzLayer
	gzConfig := mustJSON(t, map[string]any{"v": "c", "rootfs": map[string]any{"diff_ids": []string{digestOf([]byte("layer c"))}}})
	gz.config = digestOf(gzConfig)
	gz.blobs[gz.config] = gzConfig
	gzManifest := mustJSON(t, map[string]any{"config": map[string]string{"digest": gz.config}, "layers": []map[string]string{{"digest": gz.layer}}})
	gz.index = digestOf(gzManifest)
	gz.blobs[gz.index] = gzManifest
	gzFiles := map[string][]byte{}
	for d, c := range gz.blobs {
		gzFiles[blobPath(d)] = c
	}
	cases := []struct {
		name string
		meta builtImage
		tar  []byte
		want string
	}{
		{"consistent, classic", classic, build([]map[string]any{entry(a)}, []string{a.index}, nil), ""},
		{"consistent, containerd", containerd, build([]map[string]any{entry(a)}, []string{a.index}, nil), ""},
		{"compressed layer", builtImage{Name: name, Digest: gz.index, ConfigDigest: gz.config}, build([]map[string]any{entry(gz)}, []string{gz.index}, gzFiles), ""},
		// Review A 1a: the classic branch never read index.json.
		{"classic, index names another image", classic, build([]map[string]any{entry(a)}, []string{b.index}, nil), "does not name the config manifest.json names"},
		// Review A 1b, B gap 2: docker load on the containerd store gives
		// the name the last entry, b.
		{"two index entries", containerd, build([]map[string]any{entry(a)}, []string{a.index, b.index}, nil), "index.json has 2 entries"},
		{"two index entries, other first", containerd, build([]map[string]any{entry(a)}, []string{b.index, a.index}, nil), "index.json has 2 entries"},
		{"two manifest.json entries", classic, build([]map[string]any{entry(b), entry(a)}, []string{a.index}, nil), "manifest.json has 2 entries"},
		// Review B gap 1: layers that are not the config's.
		{"layer outside blobs", classic, build([]map[string]any{entry(a, "evil/layer.tar")}, []string{a.index}, map[string][]byte{"evil/layer.tar": []byte("other layer")}), "which is neither layer 1"},
		{"layer of another image", classic, build([]map[string]any{entry(a, blobPath(b.layer))}, []string{a.index}, nil), "which is neither layer 1"},
		{"extra layer", classic, build([]map[string]any{entry(a, blobPath(a.layer), blobPath(b.layer))}, []string{a.index}, nil), "names 2 layers"},
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

// TestReferencedLimit: a chain of scripts longer than the file limit is
// reported instead of being cut off silently (point 1). The last script
// saves the image, with no verify step before it.
func TestReferencedLimit(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", pinnedSyntaxLine+pinnedFrom)
	const n = 210
	for i := range n {
		body := fmt.Sprintf("#!/bin/sh\nsh scripts/s%03d.sh\n", i+1)
		if i == n-1 {
			body = "#!/bin/sh\ndocker save ghcr.io/keepia/mail-postfix:dev -o image.tar\n"
		}
		write(t, root, fmt.Sprintf("scripts/s%03d.sh", i), body)
	}
	write(t, root, ".github/workflows/ci.yml", `on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    env:
      BAKE_TARGET: postfix
    steps:
      - run: `+bakeCheckRun+`
      - id: build
        uses: docker/bake-action@59cb1203cd42bcefd40a1b6d73b589e48c86040e # v7.5.0
        with:
          source: .
          targets: ${{ env.BAKE_TARGET }}
      - run: sh scripts/s000.sh
`)
	var out, errOut bytes.Buffer
	code := run([]string{root}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "the check stops following them there") {
		t.Fatalf("exit %d, want 1 with the file limit reported:\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), filepath.ToSlash(filepath.Join(".github", "workflows", "ci.yml"))) {
		t.Errorf("the finding does not name the workflow:\n%s", out.String())
	}
}
