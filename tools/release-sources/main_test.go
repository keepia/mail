package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test 21 (#27): release-sources on fixtures shaped like syft v1.57.1's
// output (measured on the keepia and unbound images in part 4a).

const (
	cfgA   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfgB   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	commit = "0123456789abcdef0123456789abcdef01234567"
)

type deb struct{ name, version, arch, source, sourceVersion string }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// syftJSON is a syft-json document of an image with these debs and Go
// modules.
func syftJSON(t *testing.T, config string, debs []deb, gomods ...string) []byte {
	t.Helper()
	var arts []any
	for _, d := range debs {
		arts = append(arts, map[string]any{"type": "deb", "name": d.name, "version": d.version, "metadataType": "dpkg-db-entry",
			"metadata": map[string]any{"package": d.name, "source": d.source, "version": d.version, "sourceVersion": d.sourceVersion, "architecture": d.arch}})
	}
	for _, m := range gomods {
		name, version, _ := strings.Cut(m, "@")
		arts = append(arts, map[string]any{"type": "go-module", "name": name, "version": version, "metadataType": "go-module-buildinfo-entry",
			"metadata": map[string]any{"goCompiledVersion": "go1.27.4", "h1Digest": "h1:x=", "mainModule": "github.com/keepia/mail"}})
	}
	return mustJSON(t, map[string]any{"artifacts": arts, "source": map[string]any{"type": "image", "metadata": map[string]any{"imageID": config}}})
}

// spdxJSON is a minimal syft SPDX document: the image as the described
// package and one package.
func spdxJSON(t *testing.T) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "image.tar",
		"documentNamespace": "https://anchore.com/syft/image/image.tar-x",
		"creationInfo":      map[string]any{"creators": []string{"Organization: Anchore, Inc", "Tool: syft-[not provided]"}, "created": "2026-11-13T04:49:18Z"},
		"packages": []any{
			map[string]any{"name": "bash", "SPDXID": "SPDXRef-Package-deb-bash", "versionInfo": "5.2.37-2+b10"},
			map[string]any{"name": "image.tar", "SPDXID": "SPDXRef-DocumentRoot-Image-image.tar", "versionInfo": "sha256:" + strings.Repeat("9", 64)},
		},
		"relationships": []any{
			map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-DocumentRoot-Image-image.tar", "relationshipType": "DESCRIBES"},
		},
	})
}

var unboundDebs = []deb{
	{"bash", "5.2.37-2+b10", "amd64", "bash", "5.2.37-2"},
	{"libc6", "2.41-12+deb13u4", "amd64", "glibc", ""},
	{"unbound", "1.22.0-2", "amd64", "", ""},
	{"libssl3t64", "3.5.4-1~deb13u1", "amd64", "openssl", ""},
}

func packagesTxt(debs []deb) []byte {
	var b strings.Builder
	for _, d := range debs {
		b.WriteString(d.name + "\t" + d.version + "\t" + d.arch + "\n")
	}
	return []byte(b.String())
}

func labels(version string) map[string]string {
	return map[string]string{licenceKey: "MIT AND BSD-3-Clause", sourcesKey: "https://github.com/keepia/mail/releases/download/v" + version + "/SOURCES.md"}
}

const unboundDockerfile = `# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN --network=none groupadd --system unbound
RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install --mount=type=secret,id=ca,required=false,mode=0444 \
    sh /tmp/keepia-apt-install unbound dns-root-data \
      tini inotify-tools
`

func unboundRow(t *testing.T) rowInput {
	return rowInput{
		target: "unbound", platform: "linux/amd64", version: "0.1.0", commit: commit,
		tested:   mustJSON(t, map[string]any{"buildx.build.warnings": []any{}, "unbound": map[string]string{"containerimage.config.digest": cfgA}}),
		syft:     syftJSON(t, cfgA, unboundDebs),
		spdx:     spdxJSON(t),
		packages: packagesTxt(unboundDebs), hasPackages: true,
		dockerfile: []byte(unboundDockerfile), dockerfilePath: "images/unbound/Dockerfile",
		labels: labels("0.1.0"),
	}
}

func TestRow(t *testing.T) {
	sbom, src, f := buildRow(unboundRow(t))
	if len(f) > 0 {
		t.Fatal(f)
	}
	if src.Image != "mail-unbound" || src.Config != cfgA || src.Packages != 3 {
		t.Fatalf("source list %+v", src)
	}
	var doc map[string]any
	if err := json.Unmarshal(sbom, &doc); err != nil {
		t.Fatal(err)
	}
	creators := doc["creationInfo"].(map[string]any)["creators"]
	if !strings.Contains(string(mustJSON(t, creators)), syftTool) || strings.Contains(string(mustJSON(t, creators)), "not provided") {
		t.Errorf("creators %v", creators)
	}
	if sbomSubject(sbom) != cfgA {
		t.Errorf("the SBOM's subject is %q, want the tested config", sbomSubject(sbom))
	}
	urls := map[string]string{}
	for _, c := range src.Components {
		urls[c.Name] = c.URL
	}
	for name, want := range map[string]string{
		"bash":        "https://snapshot.debian.org/package/bash/5.2.37-2/",           // a binNMU: the Source: version
		"libc6":       "https://snapshot.debian.org/package/glibc/2.41-12%2Bdeb13u4/", // no source version: its own
		"unbound":     "https://snapshot.debian.org/package/unbound/1.22.0-2/",        // no Source: field
		"libssl3t64":  "https://snapshot.debian.org/package/openssl/3.5.4-1~deb13u1/", // ~ stays
		"keepia/mail": "https://github.com/keepia/mail/tree/" + commit,
	} {
		if urls[name] != want {
			t.Errorf("%s: %q, want %q", name, urls[name], want)
		}
	}
}

func TestSnapshotEscape(t *testing.T) {
	// An epoch is URL-escaped (the ':'), and so is '+'.
	for in, want := range map[string]string{"1:2.3-4": "1%3A2.3-4", "2.41-12+deb13u4": "2.41-12%2Bdeb13u4", "1.0~rc1": "1.0~rc1"} {
		if got := snapshotEscape(in); got != want {
			t.Errorf("snapshotEscape(%q) = %q, want %q", in, got, want)
		}
	}
	in := unboundRow(t)
	epoch := append([]deb{}, unboundDebs...)
	epoch = append(epoch, deb{"libsystemd0", "1:257.9-1~deb13u1", "amd64", "systemd", ""})
	in.syft, in.packages = syftJSON(t, cfgA, epoch), packagesTxt(epoch)
	_, src, f := buildRow(in)
	if len(f) > 0 {
		t.Fatal(f)
	}
	found := false
	for _, c := range src.Components {
		if c.Name == "libsystemd0" {
			found = c.URL == "https://snapshot.debian.org/package/systemd/1%3A257.9-1~deb13u1/"
		}
	}
	if !found {
		t.Errorf("the epoch version's URL is not escaped: %+v", src.Components)
	}
}

func TestRowRefused(t *testing.T) {
	cases := []struct {
		name string
		edit func(in *rowInput)
		want string
	}{
		{"packages.txt row missing in the SBOM", func(in *rowInput) {
			in.packages = append(in.packages, []byte("curl\t8.14.1-2\tamd64\n")...)
		}, "packages.txt lists curl 8.14.1-2 amd64, which is not a deb package of the SBOM"},
		{"an extra deb in the SBOM", func(in *rowInput) {
			in.syft = syftJSON(t, cfgA, append(append([]deb{}, unboundDebs...), deb{"wget", "1.25.0-2", "amd64", "", ""}))
		}, "the SBOM has the deb package wget 1.25.0-2 amd64, which packages.txt does not list"},
		{"an SBOM for the wrong ID", func(in *rowInput) { in.syft = syftJSON(t, cfgB, unboundDebs) }, "the SBOM is of the image \"" + cfgB + "\", not the tested config"},
		{"metadata without config digest", func(in *rowInput) { in.tested = []byte(`{"unbound":{"containerimage.digest":"` + cfgA + `"}}`) }, "has no containerimage.config.digest"},
		{"a target without a licences label", func(in *rowInput) { delete(in.labels, licenceKey) }, "has no org.opencontainers.image.licenses label"},
		{"a sources label of another version", func(in *rowInput) { in.labels = labels("0.0.9") }, "io.github.keepia.sources label"},
		{"an ADD of unknown form", func(in *rowInput) {
			in.dockerfile = append(in.dockerfile, []byte("ADD --checksum=sha256:"+strings.Repeat("1", 64)+" https://example.org/x.tar.gz /tmp/x.tar.gz\n")...)
		}, "matches no known URL form"},
		{"an ADD without a licence", func(in *rowInput) {
			in.dockerfile = append(in.dockerfile, []byte("ADD --checksum=sha256:"+strings.Repeat("1", 64)+" https://github.com/example/other/archive/refs/tags/v1.tar.gz /tmp/x.tar.gz\n")...)
		}, "example/other has no licence"},
		{"a networked RUN with && curl", func(in *rowInput) {
			in.dockerfile = []byte(strings.Replace(unboundDockerfile, "tini inotify-tools", "tini inotify-tools && curl -o /x https://example.org/x", 1))
		}, "a RUN without --network=none must be exactly"},
		{"&& curl on a continuation line", func(in *rowInput) {
			in.dockerfile = []byte(strings.Replace(unboundDockerfile, "tini inotify-tools\n", "tini inotify-tools \\\n      && curl https://example.org/x\n", 1))
		}, "a RUN without --network=none must be exactly"},
		{"a package name with $", func(in *rowInput) {
			in.dockerfile = []byte(strings.Replace(unboundDockerfile, "dns-root-data", "$(curl example.org)", 1))
		}, "a RUN without --network=none must be exactly"},
		{"the mount with another command", func(in *rowInput) {
			in.dockerfile = []byte(strings.Replace(unboundDockerfile, "sh /tmp/keepia-apt-install unbound", "pip install unbound", 1))
		}, "a RUN without --network=none must be exactly"},
		{"a RUN with network and no mount", func(in *rowInput) {
			in.dockerfile = append(in.dockerfile, []byte("RUN apt-get update\n")...)
		}, "a RUN without --network=none must be exactly"},
		{"no packages.txt for a Debian image", func(in *rowInput) { in.hasPackages, in.packages = false, nil }, "only the Keepia image (distroless) has none"},
		{"another platform", func(in *rowInput) { in.platform = "linux/s390x" }, "is not linux/amd64 or linux/arm64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := unboundRow(t)
			c.edit(&in)
			_, _, f := buildRow(in)
			if !strings.Contains(strings.Join(f, "\n"), c.want) {
				t.Fatalf("findings %q, want %q", f, c.want)
			}
		})
	}
}

// TestKeepiaRow: the distroless image has no packages.txt; it needs the
// base's packages, its Go modules and the toolchain.
func TestKeepiaRow(t *testing.T) {
	var base []deb
	for _, n := range distrolessBase {
		base = append(base, deb{n, "1", "all", "", ""})
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	in := rowInput{target: "keepia", platform: "linux/arm64", version: "0.1.0", commit: commit,
		tested: []byte(`{"keepia":{"containerimage.config.digest":"` + cfgA + `"}}`),
		syft:   syftJSON(t, cfgA, base, "github.com/jackc/pgx/v5@v5.11.0", "github.com/BurntSushi/toml@v1.5.0", "stdlib@go1.27.4", "github.com/keepia/mail@UNKNOWN"),
		spdx:   spdxJSON(t), dockerfile: root, dockerfilePath: "Dockerfile", labels: labels("0.1.0")}
	_, src, f := buildRow(in)
	if len(f) > 0 {
		t.Fatal(f)
	}
	var mods, tool int
	for _, c := range src.Components {
		switch c.Kind {
		case "go-module":
			mods++
			if c.Name == "github.com/BurntSushi/toml" && c.URL != "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.5.0.zip" {
				t.Errorf("the module proxy URL is not case-encoded: %s", c.URL)
			}
		case "go-toolchain":
			tool++
		}
	}
	if mods != 2 || tool != 1 {
		t.Errorf("%d modules (the main module is Keepia's own component) and %d toolchains: %+v", mods, tool, src.Components)
	}
	in.syft = syftJSON(t, cfgA, base[1:], "stdlib@go1.27.4")
	if _, _, f := buildRow(in); !strings.Contains(strings.Join(f, "\n"), "lacks the distroless base package base-files") || !strings.Contains(strings.Join(f, "\n"), "lacks its component go-module:*") {
		t.Errorf("findings %q", f)
	}
}

// TestRepositoryDockerfiles: the repository's own Dockerfiles pass the
// ADD and RUN rules, and give the components each image must have.
func TestRepositoryDockerfiles(t *testing.T) {
	want := map[string][]string{
		"Dockerfile":                {},
		"images/postfix/Dockerfile": {},
		"images/unbound/Dockerfile": {},
		"images/olefy/Dockerfile":   {"HeinleinSupport/olefy", "oletools", "pcodedmp"},
		"images/sogo/Dockerfile":    {"Alinto/sope", "Alinto/sogo"},
	}
	for rel, names := range want {
		src, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		comps, f := checkDockerfile(rel, src)
		if len(f) > 0 {
			t.Errorf("%s: %q", rel, f)
		}
		var got []string
		for _, c := range comps {
			got = append(got, c.Name)
			if !strings.HasPrefix(c.SHA256, "sha256:") || c.License == "" || c.Version == "" {
				t.Errorf("%s: %+v", rel, c)
			}
		}
		if strings.Join(got, " ") != strings.Join(names, " ") {
			t.Errorf("%s: components %v, want %v", rel, got, names)
		}
	}
	// The Go build stage is the root Dockerfile's exception only.
	src, _ := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if _, f := checkDockerfile("images/x/Dockerfile", src); len(f) == 0 {
		t.Error("the Go build stage passed outside the root Dockerfile")
	}
}

// TestRelease: exactly one SBOM and source list per image and arch, each
// for the config the push row proved.
func TestRelease(t *testing.T) {
	setup := func(t *testing.T, targets []string) (string, string) {
		in, dg := t.TempDir(), t.TempDir()
		for _, tg := range targets {
			for _, a := range archs {
				r := unboundRow(t)
				r.target, r.platform = tg, "linux/"+a
				r.tested = []byte(`{"` + tg + `":{"containerimage.config.digest":"` + cfgA + `"}}`)
				r.labels = labels("0.1.0")
				sbom, src, f := buildRow(r)
				if len(f) > 0 {
					t.Fatal(f)
				}
				if err := writeRow(in, sbom, src); err != nil {
					t.Fatal(err)
				}
				rec := digestRecord{Target: tg, Platform: "linux/" + a, Version: "0.1.0", Config: cfgA}
				if err := os.WriteFile(filepath.Join(dg, tg+"-"+a+".json"), mustJSON(t, rec), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return in, dg
	}
	targets := []string{"postfix", "unbound"}
	t.Run("ok", func(t *testing.T) {
		in, dg := setup(t, targets)
		files, f := mergeRelease("0.1.0", targets, in, dg)
		if len(f) > 0 {
			t.Fatal(f)
		}
		md := string(files["SOURCES.md"])
		for _, w := range []string{"Mechanical snail", "https://stackoverflow.com/a/20260030/4405656", "| `ghcr.io/keepia/mail-postfix:0.1.0` | `MIT AND BSD-3-Clause` |", "[glibc](https://snapshot.debian.org/package/glibc/2.41-12%2Bdeb13u4/)", "GPL-3.0-only"} {
			if !strings.Contains(md, w) {
				t.Errorf("SOURCES.md lacks %q", w)
			}
		}
		if string(files["licences.txt"]) != "mail-postfix MIT AND BSD-3-Clause\nmail-unbound MIT AND BSD-3-Clause\n" {
			t.Errorf("licences.txt %q", files["licences.txt"])
		}
		var sj struct {
			Sources []component `json:"sources"`
		}
		if err := json.Unmarshal(files["sources.json"], &sj); err != nil {
			t.Fatal(err)
		}
		for _, c := range sj.Sources {
			if c.Name == "bash" && len(c.Images) != 4 {
				t.Errorf("bash is in %v, want the 4 rows", c.Images)
			}
		}
		if !strings.Contains(string(files["summary"]), "| mail-postfix | 3 packages, 5 sources | 3 packages, 5 sources |") {
			t.Errorf("summary %s", files["summary"])
		}
	})
	t.Run("9 of 10 SBOMs", func(t *testing.T) {
		in, dg := setup(t, targets)
		if err := os.Remove(filepath.Join(in, "sbom-mail-unbound-arm64.spdx.json")); err != nil {
			t.Fatal(err)
		}
		if _, f := mergeRelease("0.1.0", targets, in, dg); !strings.Contains(strings.Join(f, "\n"), "no SBOM for mail-unbound linux/arm64") {
			t.Fatalf("findings %q", f)
		}
	})
	t.Run("an SBOM of another config", func(t *testing.T) {
		in, dg := setup(t, targets)
		rec := digestRecord{Target: "postfix", Platform: "linux/amd64", Version: "0.1.0", Config: cfgB}
		if err := os.WriteFile(filepath.Join(dg, "postfix-amd64.json"), mustJSON(t, rec), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, f := mergeRelease("0.1.0", targets, in, dg); !strings.Contains(strings.Join(f, "\n"), "but the push row proved the published config \""+cfgB) {
			t.Fatalf("findings %q", f)
		}
	})
	t.Run("a row of no image of the release", func(t *testing.T) {
		in, dg := setup(t, targets)
		if _, f := mergeRelease("0.1.0", targets[:1], in, dg); !strings.Contains(strings.Join(f, "\n"), "is not a row of this release") {
			t.Fatalf("findings %q", f)
		}
	})
}

func TestUsage(t *testing.T) {
	var out, errOut strings.Builder
	for _, args := range [][]string{nil, {"x"}, {"row"}, {"release", "-version", "v1"}} {
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}
