package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
		// #88: BuildKit skips an empty continuation line and appends the
		// next line to the RUN, so the && curl line is part of it.
		{"&& curl after an empty continuation line", func(in *rowInput) {
			in.dockerfile = []byte(strings.Replace(unboundDockerfile, "tini inotify-tools\n", "tini inotify-tools \\\n\n      && curl https://example.org/x\n", 1))
		}, "a RUN without --network=none must be exactly"},
		{"&& curl after a whitespace-only continuation line", func(in *rowInput) {
			in.dockerfile = []byte(strings.Replace(unboundDockerfile, "tini inotify-tools\n", "tini inotify-tools \\\n  \t\n      && curl https://example.org/x\n", 1))
		}, "a RUN without --network=none must be exactly"},
		// #88: an escaped backslash at a line end is no continuation
		// (BuildKit parser.go:175), so the next RUN stands alone.
		{"a RUN after a line ending in an escaped backslash", func(in *rowInput) {
			in.dockerfile = append(in.dockerfile, []byte("RUN --network=none echo \\\\\nRUN apt-get update\n")...)
		}, "a RUN without --network=none must be exactly"},
		// #88 (Review A B1 on PR #104): BuildKit writes a continuation line
		// directly after the line before it, so a keyword or a flag split
		// at the line break is one word again.
		{"a RUN keyword split over a continuation", func(in *rowInput) {
			in.dockerfile = append(in.dockerfile, []byte("RU\\\nN curl https://example.org/x\n")...)
		}, "a RUN without --network=none must be exactly"},
		{"--network=none glued to the flag before it", func(in *rowInput) {
			in.dockerfile = append(in.dockerfile, []byte("RUN --mount=type=tmpfs,target=/a\\\n--network=none curl https://example.org/x\n")...)
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

// TestGoBuildStage (#66 item 2): in the root Dockerfile's Go build stage
// only the go mod download RUN, exactly and once, may have network; each
// change of the real Dockerfile below is one finding.
func TestGoBuildStage(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	root := string(src)
	const (
		build    = "RUN --network=none CGO_ENABLED=0"
		copyCode = "COPY internal ./internal\n"
		download = " && go mod download \\\n"
		verify   = " && go mod verify\n"
	)
	for _, s := range []string{build, copyCode, download, verify} {
		if strings.Count(root, s) != 1 {
			t.Fatalf("the root Dockerfile has %q %d times, want once", s, strings.Count(root, s))
		}
	}
	modRUN := root[strings.Index(root, "RUN --mount=type=secret,id=ca,required=false"):strings.Index(root, "COPY cmd ./cmd\n")]
	if !strings.HasSuffix(modRUN, "go mod verify\n") {
		t.Fatalf("the go mod download RUN is not where the test expects it: %q", modRUN)
	}
	t.Run("the real Dockerfile", func(t *testing.T) {
		if _, f := checkDockerfile("Dockerfile", src); len(f) > 0 {
			t.Fatalf("findings %q", f)
		}
	})
	cases := []struct{ name, dockerfile string }{
		{"go build without --network=none", strings.Replace(root, build, "RUN CGO_ENABLED=0", 1)},
		{"a second networked RUN in the stage", strings.Replace(root, copyCode, copyCode+"RUN go generate ./...\n", 1)},
		{"a changed go mod download RUN", strings.Replace(root, download, " && go mod download \\\n && go install example.org/x@latest \\\n", 1)},
		{"the go mod download RUN twice", strings.Replace(root, copyCode, copyCode+modRUN, 1)},
		// #88: the blank line comes after the RUN's last line; one placed
		// earlier would already cut goModDownload short.
		{"a line after an empty continuation line", strings.Replace(root, verify, " && go mod verify \\\n\n && go install example.org/x@latest\n", 1)},
		{"a line after a form-feed continuation line", strings.Replace(root, verify, " && go mod verify \\\n\f\n && go install example.org/x@latest\n", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.dockerfile == root {
				t.Fatal("the case changes nothing")
			}
			_, f := checkDockerfile("Dockerfile", []byte(c.dockerfile))
			assertFindings(t, f, []string{"a RUN without --network=none must be exactly"})
		})
	}
}

// TestInstructions (#88): instructions joins lines as BuildKit v0.35.0's
// parser does (frontend/dockerfile/parser/parser.go): comment and empty
// lines are skipped inside a continuation too, "empty" by unicode.IsSpace;
// a line continues only when its backslash is not escaped; and a
// continuation line is appended directly, with no separator, so a word
// split at the line break is one word. The text is compared word by word,
// as checkDockerfile reads it.
func TestInstructions(t *testing.T) {
	type in = instruction
	const apt = "RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install sh /tmp/keepia-apt-install"
	cases := []struct {
		name, src string
		want      []instruction
	}{
		{"an empty line inside a continuation", "RUN a \\\n\nb\nRUN c\n", []in{{1, "RUN a b"}, {4, "RUN c"}}},
		{"a whitespace-only line inside a continuation", "RUN a \\\n \t\nb\n", []in{{1, "RUN a b"}}},
		{"a form-feed line inside a continuation", "RUN a \\\n\f\nb\n", []in{{1, "RUN a b"}}},
		{"a no-break space line inside a continuation", "RUN a \\\n\xc2\xa0\nb\n", []in{{1, "RUN a b"}}},
		{"a blank and a carriage return inside a continuation", "RUN a \\\n \r\nb\n", []in{{1, "RUN a b"}}},
		{"a comment line inside a continuation", "RUN a \\\n  # c\nb\n", []in{{1, "RUN a b"}}},
		{"a backslash followed by blanks", "RUN a \\ \t\nb\n", []in{{1, "RUN a b"}}},
		{"CRLF line endings", "RUN a \\\r\nb\r\nRUN c\r\n", []in{{1, "RUN a b"}, {3, "RUN c"}}},
		{"blank, form-feed and comment lines before an instruction", "\n\f\n# c\n \t\nRUN a\n", []in{{5, "RUN a"}}},
		{"an escaped backslash at the line end", "RUN a \\\\\nRUN x\n", []in{{1, `RUN a \\`}, {2, "RUN x"}}},
		{"an escaped backslash and blanks at the line end", "RUN a \\\\  \nRUN x\n", []in{{1, `RUN a \\`}, {2, "RUN x"}}},
		{"three backslashes at the line end (BuildKit's quirk)", "RUN a \\\\\\\nRUN x\n", []in{{1, `RUN a \\\`}, {2, "RUN x"}}},
		{"a lone backslash at the end of the file", "RUN a\n\\\n", []in{{1, "RUN a"}}},
		{"a lone backslash before an instruction", "\\\nRUN a\n", []in{{1, "RUN a"}}},
		{"an apt RUN with an empty line between package lines", apt + " a b \\\n\n    c d\n", []in{{1, apt + " a b c d"}}},
		{"a FROM keyword split over a continuation", "FR\\\nOM alpine:latest\n", []in{{1, "FROM alpine:latest"}}},
		{"a RUN keyword split over a continuation", "RU\\\nN curl https://example.org/x\n", []in{{1, "RUN curl https://example.org/x"}}},
		{"a flag glued to the next line", "RUN --mount=type=tmpfs,target=/a\\\n--network=none curl\n", []in{{1, "RUN --mount=type=tmpfs,target=/a--network=none curl"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []instruction
			for _, i := range instructions([]byte(c.src)) {
				got = append(got, instruction{i.line, strings.Join(strings.Fields(i.text), " ")})
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("instructions(%q) = %+v, want %+v", c.src, got, c.want)
			}
		})
	}
	// The apt RUN above is one RUN, so R1 accepts it: BuildKit installs
	// every package of it.
	src := strings.Replace(unboundDockerfile, "unbound dns-root-data \\\n", "unbound dns-root-data \\\n\n", 1)
	if src == unboundDockerfile {
		t.Fatal("the edit changes nothing")
	}
	if _, f := checkDockerfile("images/unbound/Dockerfile", []byte(src)); len(f) > 0 {
		t.Errorf("an empty line between package lines: findings %q", f)
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
		for _, w := range []string{"Mechanical snail", "https://stackoverflow.com/a/20260030/4405656", "| `ghcr.io/keepia/mail-postfix:0.1.0` | `MIT AND BSD-3-Clause` |", "[glibc](https://snapshot.debian.org/package/glibc/2.41-12%2Bdeb13u4/)", "GPL-3.0-only",
			"## Python and npm packages in the SBOMs\n\nThese packages are part of a component listed above, which links to their source.\n\nNone.\n"} {
			if !strings.Contains(md, w) {
				t.Errorf("SOURCES.md lacks %q", w)
			}
		}
		if strings.Contains(md, "ckeditor") {
			t.Error("SOURCES.md has the CKEditor paragraph without sogo")
		}
		if !strings.Contains(string(files["sources.json"]), "\"attributed\": []") {
			t.Errorf("sources.json has no empty attributed list:\n%s", files["sources.json"])
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
