package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real syft v1.57.1 output (#73): the olefy and sogo images, linux/amd64,
// built from main 83e4f1d with the release's bake settings, saved by
// check-image-pins -verify-built -save and scanned as release.yml does.
// testdata/<image>-amd64.packages.txt is the image's own
// /usr/share/keepia/packages.txt. The syft-json is trimmed to what
// release-sources reads, with this jq filter (written one artifact per
// line):
//
//	([.artifacts[] | select(.type != "deb") | .locations[].path]) as $refs
//	| {
//	    source: {type: .source.type, metadata: {imageID: .source.metadata.imageID}},
//	    artifacts: [.artifacts[] |
//	      if .type == "deb" then
//	        {id, type, name, version,
//	         metadata: (({package: .metadata.package, source: .metadata.source, version: .metadata.version,
//	                      sourceVersion: .metadata.sourceVersion, architecture: .metadata.architecture}
//	                     | with_entries(select(.value != "" and .value != null)))
//	                    + ([(.metadata.files // [])[] | select(.path | IN($refs[])) | {path}] as $f
//	                       | if ($f | length) > 0 then {files: $f} else {} end))}
//	      else
//	        {id, type, name, version, locations: [.locations[] | {path}]}
//	        + (if .metadata.directUrlOrigin.url then {metadata: {directUrlOrigin: {url: .metadata.directUrlOrigin.url}}} else {} end)
//	      end],
//	    artifactRelationships: [.artifactRelationships[] | select(.type == "ownership-by-file-overlap") | {parent, child, type}]
//	  }
//
// So every deb artifact stays (with the packages.txt cross-check on real
// data), a deb keeps only the files some non-deb artifact names, and only
// the ownership-by-file-overlap relationships stay.

const (
	tripletAMD64 = "/usr/lib/x86_64-linux-gnu/"
	tripletARM64 = "/usr/lib/aarch64-linux-gnu/"
)

// fixtureRow is the row input of a real image: target olefy or sogo, arch
// amd64 or arm64. The arm64 variant is the amd64 fixture with the triplet
// of the npm locations rewritten; its debs and packages.txt stay as they
// are, because it only tests the path table.
func fixtureRow(t *testing.T, target, arch string) rowInput {
	t.Helper()
	syft, err := os.ReadFile(filepath.Join("testdata", target+"-amd64.syft.json"))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := os.ReadFile(filepath.Join("testdata", target+"-amd64.packages.txt"))
	if err != nil {
		t.Fatal(err)
	}
	rel := "images/" + target + "/Dockerfile"
	df, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(syft, &doc); err != nil {
		t.Fatal(err)
	}
	if arch == "arm64" {
		syft = rewriteNPM(t, doc, tripletAMD64, tripletARM64)
	}
	config, _ := doc["source"].(map[string]any)["metadata"].(map[string]any)["imageID"].(string)
	return rowInput{
		target: target, platform: "linux/" + arch, version: "0.1.0", commit: commit,
		tested:   mustJSON(t, map[string]any{target: map[string]string{"containerimage.config.digest": config}}),
		syft:     syft,
		spdx:     spdxJSON(t),
		packages: pkgs, hasPackages: true,
		dockerfile: df, dockerfilePath: rel,
		labels: labels("0.1.0"),
	}
}

// rewriteNPM replaces from with to in the locations of the npm artifacts
// of a syft-json document and returns the document.
func rewriteNPM(t *testing.T, doc map[string]any, from, to string) []byte {
	t.Helper()
	n := 0
	for _, a := range doc["artifacts"].([]any) {
		m := a.(map[string]any)
		if m["type"] != "npm" {
			continue
		}
		for _, l := range m["locations"].([]any) {
			loc := l.(map[string]any)
			p := loc["path"].(string)
			if strings.Contains(p, from) {
				loc["path"] = strings.Replace(p, from, to, 1)
				n++
			}
		}
	}
	if n == 0 {
		t.Fatalf("no npm location holds %s", from)
	}
	return mustJSON(t, doc)
}

// TestFixturesHaveNoFindings: the real olefy and sogo rows pass row mode.
// It uses only rowInput and buildRow, so it also runs on 83e4f1d, where
// every python and npm package was a finding (#73).
func TestFixturesHaveNoFindings(t *testing.T) {
	for _, c := range []struct{ target, arch string }{{"olefy", "amd64"}, {"sogo", "amd64"}, {"sogo", "arm64"}} {
		t.Run(c.target+"-"+c.arch, func(t *testing.T) {
			_, _, f := buildRow(fixtureRow(t, c.target, c.arch))
			for _, x := range f {
				t.Errorf("finding: %s", x)
			}
			if len(f) > 0 {
				t.Errorf("%d findings, want none", len(f))
			}
		})
	}
}
