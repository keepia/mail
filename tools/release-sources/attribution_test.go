package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Tests of #73: the python and npm packages of the real olefy and sogo
// SBOMs (fixture_test.go) are attributed to a component of the row, and
// anything that only looks like them is a finding.

const (
	sogoURL      = "https://github.com/Alinto/sogo/archive/refs/tags/SOGo-5.12.13.tar.gz"
	sogoVendored = "GNUstep/SOGo/WebServerResources/"
)

// editRow is fixtureRow with its syft-json changed by edit.
func editRow(t *testing.T, target, arch string, edit func(doc map[string]any)) rowInput {
	t.Helper()
	in := fixtureRow(t, target, arch)
	var doc map[string]any
	if err := json.Unmarshal(in.syft, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	in.syft = mustJSON(t, doc)
	return in
}

// art is the artifact of a syft-json document with this name and version.
func art(doc map[string]any, name, version string) map[string]any {
	for _, a := range doc["artifacts"].([]any) {
		m := a.(map[string]any)
		if m["name"] == name && m["version"] == version {
			return m
		}
	}
	panic("no artifact " + name + " " + version)
}

func locs(paths ...string) []any {
	var l []any
	for _, p := range paths {
		l = append(l, map[string]any{"path": p})
	}
	return l
}

// ownerOf is the ownership-by-file-overlap relationship of a child id.
func ownerOf(doc map[string]any, child string) map[string]any {
	for _, r := range doc["artifactRelationships"].([]any) {
		if m := r.(map[string]any); m["child"] == child {
			return m
		}
	}
	panic("no relationship for " + child)
}

func byPackage(list []attribution) map[string]attribution {
	m := map[string]attribution{}
	for _, a := range list {
		m[a.Name+" "+a.Version] = a
	}
	return m
}

// TestRowOlefy: the 24 python packages of olefy: 22 owned by a deb, the 2
// pinned wheels by their downloads.
func TestRowOlefy(t *testing.T) {
	_, src, f := buildRow(fixtureRow(t, "olefy", "amd64"))
	if len(f) > 0 {
		t.Fatal(f)
	}
	var debian, download int
	for _, a := range src.Attributed {
		switch {
		case strings.HasPrefix(a.Component, "debian:"):
			debian++
		case strings.HasPrefix(a.Component, "download:"):
			download++
		}
		if a.Type != "python" || a.URL == "" || len(a.Locations) == 0 {
			t.Errorf("%+v", a)
		}
	}
	if len(src.Attributed) != 24 || debian != 22 || download != 2 {
		t.Fatalf("%d attributed, %d to debian and %d to download, want 24, 22 and 2: %+v", len(src.Attributed), debian, download, src.Attributed)
	}
	got := byPackage(src.Attributed)
	for pkg, want := range map[string][2]string{
		"my-test-package 1.0": {"debian:python3-pkg-resources 78.1.1-0.1 all", "https://snapshot.debian.org/package/setuptools/78.1.1-0.1/"},
		"packaging 24.2":      {"debian:python3-pkg-resources 78.1.1-0.1 all", "https://snapshot.debian.org/package/setuptools/78.1.1-0.1/"},
		"packaging 25.0":      {"debian:python3-packaging 25.0-1 all", "https://snapshot.debian.org/package/python-packaging/25.0-1/"},
		"bcrypt 4.2.0":        {"debian:python3-bcrypt 4.2.0-2.1+b1 amd64", "https://snapshot.debian.org/package/python-bcrypt/4.2.0-2.1/"},
		"oletools 0.60.2":     {"download:oletools", "https://files.pythonhosted.org/packages/ac/ff/05257b7183279b80ecec6333744de23f48f0faeeba46c93e6d13ce835515/oletools-0.60.2-py2.py3-none-any.whl"},
		"pcodedmp 1.2.6":      {"download:pcodedmp", "https://files.pythonhosted.org/packages/ba/72/b380fb5c89d89c3afafac8cf02a71a45f4f4a4f35531ca949a34683962d1/pcodedmp-1.2.6-py2.py3-none-any.whl"},
	} {
		if a := got[pkg]; a.Component != want[0] || a.URL != want[1] {
			t.Errorf("%s: %q %q, want %q %q", pkg, a.Component, a.URL, want[0], want[1])
		}
	}
	if l := got["my-test-package 1.0"].Locations; len(l) != 2 || !strings.HasSuffix(l[0], "/EGG-INFO/PKG-INFO") {
		t.Errorf("my-test-package's locations %q", l)
	}
}

// TestRowSogo: both npm packages of sogo are part of the SOGo archive, on
// each arch with its own path.
func TestRowSogo(t *testing.T) {
	for _, arch := range archs {
		t.Run(arch, func(t *testing.T) {
			_, src, f := buildRow(fixtureRow(t, "sogo", arch))
			if len(f) > 0 {
				t.Fatal(f)
			}
			if len(src.Attributed) != 2 {
				t.Fatalf("%+v", src.Attributed)
			}
			prefix := "/usr/lib/" + triplets[arch] + "/" + sogoVendored
			for _, a := range src.Attributed {
				if a.Type != "npm" || a.Component != "download:Alinto/sogo" || a.URL != sogoURL || len(a.Locations) != 1 || !strings.HasPrefix(a.Locations[0], prefix) {
					t.Errorf("%+v, want under %s", a, prefix)
				}
			}
		})
	}
}

// TestAttributionRefused: each case changes a real row and must give
// exactly the findings it names, each naming its package.
func TestAttributionRefused(t *testing.T) {
	const (
		amdNPM   = "/usr/lib/x86_64-linux-gnu/" + sogoVendored + "js/vendor/ckeditor/package.json"
		armNPM   = "/usr/lib/aarch64-linux-gnu/" + sogoVendored + "js/vendor/ckeditor/package.json"
		ac       = "python package autocommand 2.2.2"
		ole      = "python package oletools 0.60.2"
		am       = "npm package angular-material 1.2.4"
		ck       = "npm package ckeditor5-custom-build 0.0.1"
		noOwner  = "which no Debian package owns, no pinned wheel matches and no vendored path covers"
		autoID   = "df4e2ff50c793af0"
		oleID    = "99c2f7e30949b227"
		autoMeta = "/usr/lib/python3/dist-packages/autocommand-2.2.2.dist-info/METADATA"
	)
	noSogoADD := func(in *rowInput) {
		var keep []string
		for _, l := range strings.Split(string(in.dockerfile), "\n") {
			if !strings.Contains(l, "https://github.com/Alinto/sogo/archive/") {
				keep = append(keep, l)
			}
		}
		in.dockerfile = []byte(strings.Join(keep, "\n"))
	}
	cases := []struct {
		name         string
		target, arch string
		edit         func(doc map[string]any)
		in           func(in *rowInput)
		want         []string
	}{
		// The precondition (plan review B1).
		{"npm with an empty locations list", "sogo", "amd64", func(d map[string]any) { art(d, "angular-material", "1.2.4")["locations"] = []any{} }, nil,
			[]string{am + " with no location"}},
		{"npm without the locations field", "sogo", "amd64", func(d map[string]any) { delete(art(d, "angular-material", "1.2.4"), "locations") }, nil,
			[]string{am + " with no location"}},
		{"python with a deb owner and no locations", "olefy", "amd64", func(d map[string]any) { art(d, "autocommand", "2.2.2")["locations"] = []any{} }, nil,
			[]string{ac + " with no location"}},
		{"a relative location", "olefy", "amd64", func(d map[string]any) {
			art(d, "autocommand", "2.2.2")["locations"] = locs("usr/lib/python3/dist-packages/autocommand-2.2.2.dist-info/METADATA")
		}, nil, []string{ac + " at \"usr/lib/python3/dist-packages/autocommand-2.2.2.dist-info/METADATA\", which is not an absolute path"}},
		{"an empty location path", "sogo", "amd64", func(d map[string]any) { art(d, "angular-material", "1.2.4")["locations"] = locs("") }, nil,
			[]string{am + " at \"\", which is not an absolute path"}},
		{"the location /", "sogo", "amd64", func(d map[string]any) { art(d, "angular-material", "1.2.4")["locations"] = locs("/") }, nil,
			[]string{am + " at /, " + noOwner}},
		// Rule 1.
		{"an unknown python package", "olefy", "amd64", func(d map[string]any) {
			d["artifacts"] = append(d["artifacts"].([]any), map[string]any{"id": "0123456789abcdef", "type": "python", "name": "unknown", "version": "1.0",
				"locations": locs("/usr/local/lib/python3.13/dist-packages/unknown-1.0.dist-info/METADATA")})
		}, nil, []string{"python package unknown 1.0 at /usr/local/lib/python3.13/dist-packages/unknown-1.0.dist-info/METADATA, " + noOwner}},
		{"a contains relationship instead of ownership", "olefy", "amd64", func(d map[string]any) { ownerOf(d, autoID)["type"] = "contains" }, nil,
			[]string{ac + " at " + autoMeta}},
		{"an owner that is not a deb", "olefy", "amd64", func(d map[string]any) { ownerOf(d, autoID)["parent"] = oleID }, nil,
			[]string{ac + " at " + autoMeta}},
		// Only the type differs from the real owner (#51 item 14): name,
		// version, architecture and file list are python3-autocommand's.
		{"an owner that is a deb in all but its type", "olefy", "amd64", func(d map[string]any) {
			owner := art(d, "python3-autocommand", "2.2.2-3")
			d["artifacts"] = append(d["artifacts"].([]any), map[string]any{"id": "0123456789abcdef", "type": "binary",
				"name": owner["name"], "version": owner["version"], "metadata": owner["metadata"]})
			ownerOf(d, autoID)["parent"] = "0123456789abcdef"
		}, nil, []string{"binary package python3-autocommand 2.2.2-3 with no location", ac + " at " + autoMeta}},
		{"an owner that is not in the SBOM", "olefy", "amd64", func(d map[string]any) { ownerOf(d, autoID)["parent"] = "0000000000000000" }, nil,
			[]string{ac + " at " + autoMeta}},
		{"an owner whose files lack a location", "olefy", "amd64", func(d map[string]any) {
			art(d, "python3-autocommand", "2.2.2-3")["metadata"].(map[string]any)["files"] = locs(autoMeta)
		}, nil, []string{ac + " at " + autoMeta}},
		// File lists (#51 item 15): only a deb's is read, and one that does
		// not decode is a finding naming that deb, not a parse failure.
		{"a java-archive package with its files as strings", "olefy", "amd64", func(d map[string]any) {
			d["artifacts"] = append(d["artifacts"].([]any), map[string]any{"id": "0123456789abcdef", "type": "java-archive", "name": "x", "version": "1.0",
				"locations": locs("/usr/share/java/x.jar"), "metadata": map[string]any{"files": []any{"/a", "/b"}}})
		}, nil, []string{"java-archive package x 1.0 at /usr/share/java/x.jar, " + noOwner}},
		{"an owner whose file list does not decode", "olefy", "amd64", func(d map[string]any) {
			art(d, "python3-autocommand", "2.2.2-3")["metadata"].(map[string]any)["files"] = []any{autoMeta}
		}, nil, []string{"the SBOM's deb package python3-autocommand 2.2.2-3 all has a file list that does not parse", ac + " at " + autoMeta}},
		// Rule 2.
		{"a wheel of another version", "olefy", "amd64", func(d map[string]any) { art(d, "oletools", "0.60.2")["version"] = "0.60.1" }, nil,
			[]string{"python package oletools 0.60.1 at"}},
		{"a wheel from another file", "olefy", "amd64", func(d map[string]any) {
			art(d, "oletools", "0.60.2")["metadata"] = map[string]any{"directUrlOrigin": map[string]any{"url": "file:///tmp/wheels/oletools-0.60.2-py3-none-any.whl"}}
		}, nil, []string{ole + " at"}},
		{"a wheel without directUrlOrigin", "olefy", "amd64", func(d map[string]any) { delete(art(d, "oletools", "0.60.2"), "metadata") }, nil,
			[]string{ole + " at"}},
		{"a wheel from an https URL", "olefy", "amd64", func(d map[string]any) {
			art(d, "oletools", "0.60.2")["metadata"] = map[string]any{"directUrlOrigin": map[string]any{"url": "https://example.org/x/oletools-0.60.2-py2.py3-none-any.whl"}}
		}, nil, []string{ole + " at"}},
		{"an npm package named like the wheel", "olefy", "amd64", func(d map[string]any) { art(d, "oletools", "0.60.2")["type"] = "npm" }, nil,
			[]string{"npm package oletools 0.60.2 at"}},
		// Rule 3.
		{"npm outside the prefix", "sogo", "amd64", func(d map[string]any) {
			art(d, "angular-material", "1.2.4")["locations"] = locs("/usr/share/nodejs/x/package.json")
		}, nil, []string{am + " at /usr/share/nodejs/x/package.json, " + noOwner}},
		{"one amd64 path in the arm64 row", "sogo", "arm64", func(d map[string]any) { art(d, "ckeditor5-custom-build", "0.0.1")["locations"] = locs(amdNPM) }, nil,
			[]string{ck + " at " + amdNPM}},
		{"python under the prefix", "sogo", "amd64", func(d map[string]any) { art(d, "angular-material", "1.2.4")["type"] = "python" }, nil,
			[]string{"python package angular-material 1.2.4 at"}},
		{"a location escaping the prefix", "sogo", "amd64", func(d map[string]any) {
			art(d, "angular-material", "1.2.4")["locations"] = locs("/usr/lib/x86_64-linux-gnu/" + sogoVendored + "../../../../../tmp/x/package.json")
		}, nil, []string{am + " at /usr/tmp/x/package.json, " + noOwner}},
		{"a sibling of the prefix", "sogo", "amd64", func(d map[string]any) {
			art(d, "angular-material", "1.2.4")["locations"] = locs("/usr/lib/x86_64-linux-gnu/GNUstep/SOGo/WebServerResourcesX/js/package.json")
		}, nil, []string{am + " at /usr/lib/x86_64-linux-gnu/GNUstep/SOGo/WebServerResourcesX/js/package.json, " + noOwner}},
		{"one location in and one out", "sogo", "arm64", func(d map[string]any) {
			art(d, "ckeditor5-custom-build", "0.0.1")["locations"] = locs(armNPM, "/usr/share/nodejs/x/package.json")
		}, nil, []string{ck + " at " + armNPM + ", /usr/share/nodejs/x/package.json"}},
		{"sogo's npm package in the olefy row", "olefy", "amd64", func(d map[string]any) {
			d["artifacts"] = append(d["artifacts"].([]any), map[string]any{"id": "0123456789abcdef", "type": "npm", "name": "ckeditor5-custom-build", "version": "0.0.1", "locations": locs(amdNPM)})
		}, nil, []string{ck + " at " + amdNPM}},
		{"sogo without its ADD", "sogo", "amd64", func(map[string]any) {}, noSogoADD, []string{
			"the image lacks its component download:Alinto/sogo",
			"the vendored path table names download:Alinto/sogo for npm packages under /usr/lib/{triplet}/GNUstep/SOGo/WebServerResources/, which this row does not have",
			am + " at", ck + " at",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := editRow(t, c.target, c.arch, c.edit)
			if c.in != nil {
				c.in(&in)
			}
			_, _, f := buildRow(in)
			assertFindings(t, f, c.want)
		})
	}
	// An entry whose component the row lacks is one finding, also when no
	// package uses it (a test table, passed in; vendored stays as it is).
	t.Run("a table entry for a row without its component", func(t *testing.T) {
		table := map[string][]vendoredPath{"unbound": vendored["sogo"]}
		_, _, f := buildRowWith(unboundRow(t), table)
		assertFindings(t, f, []string{"the vendored path table names download:Alinto/sogo for npm packages"})
	})
}

// assertFindings: exactly one finding per want, each containing it.
func assertFindings(t *testing.T, f, want []string) {
	t.Helper()
	if len(f) != len(want) {
		t.Fatalf("%d findings %q, want %d: %q", len(f), f, len(want), want)
	}
	left := append([]string{}, f...)
	for _, w := range want {
		found := -1
		for i, x := range left {
			if strings.Contains(x, w) {
				found = i
				break
			}
		}
		if found < 0 {
			t.Fatalf("no finding with %q in %q", w, f)
		}
		left = append(left[:found], left[found+1:]...)
	}
}

func TestPypiName(t *testing.T) {
	for in, want := range map[string]string{"oletools": "oletools", "Foo__Bar": "foo-bar", "zope.interface": "zope-interface", "a-_.b": "a-b"} {
		if got := pypiName(in); got != want {
			t.Errorf("pypiName(%q) = %q, want %q", in, got, want)
		}
	}
	for name := range addLicences {
		if !strings.Contains(name, "/") && pypiName(name) != name {
			t.Errorf("addLicences key %q is not a normalised PyPI name", name)
		}
	}
}

// TestVendoredTable: every entry is an absolute prefix ending in /, of a
// component the image must have.
func TestVendoredTable(t *testing.T) {
	for target, entries := range vendored {
		for _, e := range entries {
			if !strings.HasPrefix(e.Prefix, "/") || !strings.HasSuffix(e.Prefix, "/") || e.Type == "" {
				t.Errorf("%s: %+v", target, e)
			}
			found := false
			for _, r := range requiredComponents[target] {
				found = found || r == e.Component
			}
			if !found {
				t.Errorf("%s: %s is not one of its requiredComponents", target, e.Component)
			}
		}
	}
}

// TestReleaseAttributed: the merged list of the release has no locations
// (they differ per arch) and each image once; every row keeps its own
// locations; SOURCES.md lists the packages, and the CKEditor paragraph
// only with sogo.
func TestReleaseAttributed(t *testing.T) {
	in, dg := t.TempDir(), t.TempDir()
	targets := []string{"olefy", "sogo"}
	for _, tg := range targets {
		for _, a := range archs {
			r := fixtureRow(t, tg, a)
			if tg == "sogo" && a == "amd64" {
				// One package at two paths in one row: one entry, one image.
				var doc map[string]any
				if err := json.Unmarshal(r.syft, &doc); err != nil {
					t.Fatal(err)
				}
				doc["artifacts"] = append(doc["artifacts"].([]any), map[string]any{"id": "0123456789abcdef", "type": "npm", "name": "angular-material", "version": "1.2.4",
					"locations": locs("/usr/lib/x86_64-linux-gnu/" + sogoVendored + "js/vendor/other/package.json")})
				r.syft = mustJSON(t, doc)
			}
			sbom, src, f := buildRow(r)
			if len(f) > 0 {
				t.Fatal(f)
			}
			if err := writeRow(in, sbom, src); err != nil {
				t.Fatal(err)
			}
			rec := digestRecord{Target: tg, Platform: "linux/" + a, Version: "0.1.0", Config: src.Config}
			if err := os.WriteFile(filepath.Join(dg, tg+"-"+a+".json"), mustJSON(t, rec), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	files, f := mergeRelease("0.1.0", targets, in, dg)
	if len(f) > 0 {
		t.Fatal(f)
	}
	var sj struct {
		Images []struct {
			Image, Platform string
			Attributed      []attribution `json:"attributed"`
		} `json:"images"`
		Attributed []map[string]any `json:"attributed"`
	}
	if err := json.Unmarshal(files["sources.json"], &sj); err != nil {
		t.Fatal(err)
	}
	if len(sj.Attributed) != 26 {
		t.Errorf("%d merged entries, want 24 olefy and 2 sogo packages", len(sj.Attributed))
	}
	for _, m := range sj.Attributed {
		if _, ok := m["locations"]; ok {
			t.Errorf("a merged entry with locations: %v", m)
		}
		var images []string
		for _, i := range m["images"].([]any) {
			images = append(images, i.(string))
		}
		sort.Strings(images)
		want := "mail-olefy linux/amd64,mail-olefy linux/arm64"
		if m["type"] == "npm" {
			want = "mail-sogo linux/amd64,mail-sogo linux/arm64"
		}
		if strings.Join(images, ",") != want {
			t.Errorf("%v: images %q, want %s", m["name"], images, want)
		}
	}
	for _, r := range sj.Images {
		for _, a := range r.Attributed {
			x86 := strings.Contains(strings.Join(a.Locations, " "), "x86_64-linux-gnu")
			if len(a.Locations) == 0 || (r.Platform == "linux/arm64" && x86) || (r.Image == "mail-sogo" && r.Platform == "linux/amd64" && !x86) {
				t.Errorf("%s %s: %+v", r.Image, r.Platform, a)
			}
			if r.Image == "mail-sogo" && r.Platform == "linux/amd64" && a.Name == "angular-material" && len(a.Locations) != 2 {
				t.Errorf("angular-material at two paths: %+v", a)
			}
		}
	}
	md := string(files["SOURCES.md"])
	for _, w := range []string{
		"; Python and npm packages that syft finds inside those are listed with the component they are part of.",
		"\n## Python and npm packages in the SBOMs\n\nThese packages are part of a component listed above, which links to their source.\n",
		"| my-test-package | `1.0` | python | [debian:python3-pkg-resources 78.1.1-0.1 all](https://snapshot.debian.org/package/setuptools/78.1.1-0.1/) | mail-olefy linux/amd64, mail-olefy linux/arm64 |",
		"| oletools | `0.60.2` | python | [download:oletools](https://files.pythonhosted.org/packages/ac/ff/05257b7183279b80ecec6333744de23f48f0faeeba46c93e6d13ce835515/oletools-0.60.2-py2.py3-none-any.whl) | mail-olefy linux/amd64, mail-olefy linux/arm64 |",
		"| angular-material | `1.2.4` | npm | [download:Alinto/sogo](" + sogoURL + ") | mail-sogo linux/amd64, mail-sogo linux/arm64 |",
		"`ckeditor5-custom-build` in `mail-sogo` is the CKEditor 5 build vendored in SOGo's `js/vendor/ckeditor`",
	} {
		if !strings.Contains(md, w) {
			t.Errorf("SOURCES.md lacks %q", w)
		}
	}
	// Without sogo: no CKEditor paragraph.
	md = string(renderSources("0.1.0", nil, nil, []attribution{{Type: "python", Name: "pip", Version: "25.1.1", Component: "debian:python3-pip 25.1.1+dfsg-1 all", URL: "https://snapshot.debian.org/package/python-pip/25.1.1%2Bdfsg-1/"}}))
	if strings.Contains(md, "ckeditor") || !strings.Contains(md, "| pip | `25.1.1` | python |") {
		t.Errorf("SOURCES.md without sogo:\n%s", md)
	}
}
