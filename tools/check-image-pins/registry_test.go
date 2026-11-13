package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeRegistry is GHCR for the tool modes' tests: refs to raw manifests,
// configs by manifest ref, and every call recorded. create builds the
// index imagetools would: the image and attestation manifests of every
// source index, with the given annotations; a single source index is
// copied as it is (the same digest, measured in the plan review).
type fakeRegistry struct {
	t       *testing.T
	refs    map[string][]byte
	configs map[string][]byte
	errs    map[string]error
	// notFoundOnce answers "not found" for a ref once, then normally.
	notFoundOnce map[string]bool
	calls        []string
	creates      [][]string
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	return &fakeRegistry{t: t, refs: map[string][]byte{}, configs: map[string][]byte{}, errs: map[string]error{}, notFoundOnce: map[string]bool{}}
}

func (f *fakeRegistry) raw(ref string) ([]byte, error) {
	f.calls = append(f.calls, "raw "+ref)
	if f.notFoundOnce[ref] {
		delete(f.notFoundOnce, ref)
		return nil, fmt.Errorf("%w: ERROR: %s: not found", errNotFound, ref)
	}
	if err, ok := f.errs[ref]; ok {
		return nil, err
	}
	b, ok := f.refs[ref]
	if !ok {
		return nil, fmt.Errorf("%w: ERROR: %s: not found", errNotFound, ref)
	}
	return b, nil
}

func (f *fakeRegistry) config(ref string) ([]byte, error) {
	f.calls = append(f.calls, "config "+ref)
	if err, ok := f.errs[ref]; ok {
		return nil, err
	}
	b, ok := f.configs[ref]
	if !ok {
		return nil, errNotFound
	}
	return b, nil
}

func (f *fakeRegistry) create(args []string) error {
	f.calls = append(f.calls, "create")
	f.creates = append(f.creates, slices.Clone(args))
	var tag string
	ann := map[string]string{}
	var sources []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			i++
			tag = args[i]
		case "--annotation":
			i++
			k, v, _ := strings.Cut(strings.TrimPrefix(args[i], "index:"), "=")
			ann[k] = v
		default:
			sources = append(sources, args[i])
		}
	}
	if len(sources) == 1 && len(ann) == 0 {
		f.refs[tag] = f.refs[sources[0]]
		return nil
	}
	var manifests []any
	for _, s := range sources {
		var idx struct {
			Manifests []any `json:"manifests"`
		}
		if err := json.Unmarshal(f.refs[s], &idx); err != nil {
			f.t.Fatal(err)
		}
		manifests = append(manifests, idx.Manifests...)
	}
	b := mustJSON(f.t, map[string]any{"schemaVersion": 2, "mediaType": ociIndexType, "manifests": manifests, "annotations": ann})
	f.refs[tag] = b
	f.refs[tag[:strings.LastIndex(tag, ":")]+"@"+sha256Of(b)] = b
	return nil
}

const testRepo = "ghcr.io/keepia/mail-postfix"

// pushRow puts a pushed row of repo into the registry and returns its
// digest file record.
func pushRow(t *testing.T, reg *fakeRegistry, repo, arch, seed, version string) pushedRecord {
	t.Helper()
	img := newOCIImage(t, arch, seed, nil)
	reg.refs[repo+"@"+img.index] = img.indexJSON
	for d, b := range img.blobs {
		reg.refs[repo+"@"+d] = b
	}
	reg.configs[repo+"@"+img.manifest] = mustJSON(t, map[string]any{"config": map[string]any{"Labels": map[string]string{versionKey: version}}})
	target := strings.TrimPrefix(strings.TrimPrefix(repo, releaseRegistry+"/mail"), "-")
	if target == "" {
		target = "keepia"
	}
	return pushedRecord{Target: target, Platform: "linux/" + arch, Repository: repo, Version: version, Index: img.index, Manifest: img.manifest, Config: img.config}
}

func writeRecords(t *testing.T, dir string, recs ...pushedRecord) {
	t.Helper()
	for _, r := range recs {
		if err := writePushedRecord(dir, r); err != nil {
			t.Fatal(err)
		}
	}
}

func fixedRepos(targets ...string) bakeRepos {
	return func(version string) (map[string]string, error) {
		out := map[string]string{}
		for _, t := range targets {
			out[t] = imageRepo(t)
		}
		return out, nil
	}
}

// publishedIndex is what -publish-index creates for two rows.
func publishedIndex(t *testing.T, reg *fakeRegistry, repo, version string, amd, arm pushedRecord) string {
	t.Helper()
	if err := reg.create([]string{"-t", repo + ":" + version, "--annotation", "index:" + versionKey + "=" + version, repo + "@" + amd.Index, repo + "@" + arm.Index}); err != nil {
		t.Fatal(err)
	}
	reg.creates = nil
	return sha256Of(reg.refs[repo+":"+version])
}

// TestPublishIndex is test 20 for -publish-index: everything is checked
// before any create, X.Y.Z is never overwritten, identical content is a
// no-op.
func TestPublishIndex(t *testing.T) {
	type setup struct {
		reg  *fakeRegistry
		dir  string
		amd  pushedRecord
		arm  pushedRecord
		deps publishDeps
	}
	newSetup := func(t *testing.T) setup {
		reg := newFakeRegistry(t)
		s := setup{reg: reg, dir: t.TempDir()}
		s.amd = pushRow(t, reg, testRepo, "amd64", "a", "0.1.0")
		s.arm = pushRow(t, reg, testRepo, "arm64", "b", "0.1.0")
		s.deps = publishDeps{reg: reg, repos: fixedRepos("postfix")}
		return s
	}
	t.Run("publishes", func(t *testing.T) {
		s := newSetup(t)
		writeRecords(t, s.dir, s.amd, s.arm)
		got, f := publishIndex("0.1.0", s.dir, s.deps)
		if len(f) > 0 {
			t.Fatal(f)
		}
		want := [][]string{{"-t", testRepo + ":0.1.0", "--annotation", "index:org.opencontainers.image.version=0.1.0", testRepo + "@" + s.amd.Index, testRepo + "@" + s.arm.Index}}
		if !slices.EqualFunc(s.reg.creates, want, slices.Equal) {
			t.Fatalf("create argv %q, want %q", s.reg.creates, want)
		}
		if got[testRepo] != sha256Of(s.reg.refs[testRepo+":0.1.0"]) {
			t.Fatalf("digests %v", got)
		}
	})
	t.Run("identical content is a no-op", func(t *testing.T) {
		s := newSetup(t)
		writeRecords(t, s.dir, s.amd, s.arm)
		d := publishedIndex(t, s.reg, testRepo, "0.1.0", s.amd, s.arm)
		got, f := publishIndex("0.1.0", s.dir, s.deps)
		if len(f) > 0 || len(s.reg.creates) != 0 || got[testRepo] != d {
			t.Fatalf("findings %q, creates %q, digests %v", f, s.reg.creates, got)
		}
	})
	refused := []struct {
		name  string
		setup func(t *testing.T, s *setup)
		want  string
	}{
		{"existing X.Y.Z of other content", func(t *testing.T, s *setup) {
			other := pushRow(t, s.reg, testRepo, "amd64", "c", "0.1.0")
			publishedIndex(t, s.reg, testRepo, "0.1.0", other, s.arm)
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "exists with other content"},
		{"existing X.Y.Z without the annotation", func(t *testing.T, s *setup) {
			if err := s.reg.create([]string{"-t", testRepo + ":0.1.0", testRepo + "@" + s.amd.Index, testRepo + "@" + s.arm.Index}); err != nil {
				t.Fatal(err)
			}
			s.reg.creates = nil
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "exists with other content"},
		{"config is not the tested one", func(t *testing.T, s *setup) {
			s.amd.Config = "sha256:" + strings.Repeat("7", 64)
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "want the tested config"},
		{"wrong platform", func(t *testing.T, s *setup) {
			swapped := s.amd
			swapped.Index, swapped.Manifest, swapped.Config = s.arm.Index, s.arm.Manifest, s.arm.Config
			writeRecords(t, s.dir, swapped, s.arm)
		}, "is not linux/amd64"},
		{"three platforms", func(t *testing.T, s *setup) {
			third := newOCIImage(t, "amd64", "d", func(m []map[string]any) []map[string]any {
				return append(m, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": s.arm.Manifest, "platform": map[string]string{"os": "linux", "architecture": "arm64"}})
			})
			s.reg.refs[testRepo+"@"+third.index] = third.indexJSON
			s.amd.Index, s.amd.Manifest, s.amd.Config = third.index, third.manifest, third.config
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "holds 2 image manifests"},
		{"malformed digest", func(t *testing.T, s *setup) {
			s.amd.Index = "sha256:abc"
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "a digest is not sha256:<64 hex>"},
		{"missing row", func(t *testing.T, s *setup) {
			writeRecords(t, s.dir, s.amd)
		}, "postfix-arm64.json is missing"},
		{"a row of another version", func(t *testing.T, s *setup) {
			s.arm.Version = "0.0.9"
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "not for its own name at 0.1.0"},
		// #75 (D2): a push-rehearsal record names the repository it was
		// pushed to, so it never feeds -publish-index.
		{"a rehearsal record", func(t *testing.T, s *setup) {
			s.arm.Repository = "localhost:5000/keepia/mail-postfix"
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "postfix-arm64.json is for postfix localhost:5000/keepia/mail-postfix linux/arm64 at 0.1.0, not for its own name at 0.1.0"},
		{"registry content is not its digest", func(t *testing.T, s *setup) {
			s.reg.refs[testRepo+"@"+s.amd.Index] = []byte(`{"other":1}`)
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "has the content of"},
		// Review B, N4: one "not found" is not enough; the second
		// inspection finds the existing X.Y.Z (of other content here).
		{"not found once, then found", func(t *testing.T, s *setup) {
			other := pushRow(t, s.reg, testRepo, "amd64", "c", "0.1.0")
			publishedIndex(t, s.reg, testRepo, "0.1.0", other, s.arm)
			s.reg.notFoundOnce[testRepo+":0.1.0"] = true
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "not found, then found on the second inspection"},
		{"registry error on the tag", func(t *testing.T, s *setup) {
			s.reg.errs[testRepo+":0.1.0"] = errors.New("connection reset")
			writeRecords(t, s.dir, s.amd, s.arm)
		}, "X.Y.Z is never overwritten"},
		{"another image fails", func(t *testing.T, s *setup) {
			s.deps.repos = fixedRepos("postfix", "olefy")
			o := pushRow(t, s.reg, imageRepo("olefy"), "amd64", "e", "0.1.0")
			o2 := pushRow(t, s.reg, imageRepo("olefy"), "arm64", "f", "0.1.0")
			o2.Config = "sha256:" + strings.Repeat("6", 64)
			writeRecords(t, s.dir, s.amd, s.arm, o, o2)
		}, "want the tested config"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			s := newSetup(t)
			c.setup(t, &s)
			_, f := publishIndex("0.1.0", s.dir, s.deps)
			if !strings.Contains(strings.Join(f, "\n"), c.want) {
				t.Fatalf("findings %q, want %q", f, c.want)
			}
			if len(s.reg.creates) != 0 {
				t.Fatalf("refused, but create ran: %q", s.reg.creates)
			}
		})
	}
	t.Run("not semver", func(t *testing.T) {
		s := newSetup(t)
		if _, f := publishIndex("v0.1.0", s.dir, s.deps); len(f) != 1 || len(s.reg.calls) != 0 {
			t.Fatalf("findings %q, calls %q", f, s.reg.calls)
		}
	})
}

const (
	runSHA   = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	otherSHA = "0123456789012345678901234567890123456789"
	tagObj   = "fedcbafedcbafedcbafedcbafedcbafedcbafedc"
)

func lsRemoteOf(lines ...string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(strings.Join(lines, "\n") + "\n"), nil }
}

// latestSetup is a registry with X.Y.Z published for VERSION and,
// optionally, latest at another version.
type latestSetup struct {
	reg     *fakeRegistry
	digests string
	digest  string
}

func newLatestSetup(t *testing.T, version, latest string) latestSetup {
	t.Helper()
	reg := newFakeRegistry(t)
	amd := pushRow(t, reg, testRepo, "amd64", "a"+version, version)
	arm := pushRow(t, reg, testRepo, "arm64", "b"+version, version)
	d := publishedIndex(t, reg, testRepo, version, amd, arm)
	if latest != "" {
		la := pushRow(t, reg, testRepo, "amd64", "a"+latest, latest)
		lb := pushRow(t, reg, testRepo, "arm64", "b"+latest, latest)
		publishedIndex(t, reg, testRepo, latest, la, lb)
		reg.refs[testRepo+":latest"] = reg.refs[testRepo+":"+latest]
	}
	reg.calls = nil
	return latestSetup{reg: reg, digest: d, digests: `{"` + testRepo + `":"` + d + `"}`}
}

// TestMoveLatest is test 20 for -move-latest (revisions 4 and 5),
// including both tag forms: a lightweight v$VERSION (the release job's
// refs API tag) moves; an annotated one moves through its ^{} line and is
// refused without it.
func TestMoveLatest(t *testing.T) {
	light := func(v, sha string) string { return sha + "\trefs/tags/v" + v }
	cases := []struct {
		name, version, latest string
		git                   func() ([]byte, error)
		edit                  func(s *latestSetup)
		moves                 bool
		want                  string // "" for success
		noRegistry            bool   // refused at step 0: no registry call at all
	}{
		{"absent latest, lightweight tag", "0.1.0", "", lsRemoteOf(light("0.1.0", runSHA)), nil, true, "", false},
		{"annotated tag with its ^{} line", "0.1.0", "", lsRemoteOf(tagObj+"\trefs/tags/v0.1.0", runSHA+"\trefs/tags/v0.1.0^{}"), nil, true, "", false},
		{"annotated tag without ^{}", "0.1.0", "", lsRemoteOf(tagObj + "\trefs/tags/v0.1.0"), nil, false, "points to " + tagObj, true},
		{"forward 0.9.0 to 0.10.0", "0.10.0", "0.9.0", lsRemoteOf(light("0.9.0", otherSHA), light("0.10.0", runSHA)), nil, true, "", false},
		{"same version, same digest", "0.1.0", "0.1.0", lsRemoteOf(light("0.1.0", runSHA)), nil, false, "", false},
		{"not found while a newer tag exists", "0.2.0", "", lsRemoteOf(light("0.2.0", runSHA), light("0.3.0", otherSHA)), nil, false, "the highest release tag is v0.3.0", true},
		{"0.10.0 to 0.9.1 (highest v0.10.0)", "0.9.1", "0.10.0", lsRemoteOf(light("0.10.0", otherSHA), light("0.9.1", runSHA)), nil, false, "the highest release tag is v0.10.0", true},
		{"latest 0.10.0 by label, highest v0.9.1", "0.9.1", "0.10.0", lsRemoteOf(light("0.9.1", runSHA)), nil, false, "would not be forward", false},
		{"v0.10.0 and v0.9.9, VERSION 0.9.9", "0.9.9", "", lsRemoteOf(light("0.9.9", runSHA), light("0.10.0", otherSHA)), nil, false, "the highest release tag is v0.10.0", true},
		{"highest tag on another commit", "0.1.0", "", lsRemoteOf(light("0.1.0", otherSHA)), nil, false, "points to " + otherSHA, true},
		{"git fails", "0.1.0", "", func() ([]byte, error) { return nil, errors.New("exit status 128: could not resolve host") }, nil, false, "could not resolve host", true},
		{"no semver tag", "0.1.0", "", lsRemoteOf(light("1.0.0-rc1", runSHA), runSHA+"\trefs/tags/v01.0.0", runSHA+"\trefs/tags/release"), nil, false, "no vX.Y.Z tag", true},
		{"empty answer", "0.1.0", "", func() ([]byte, error) { return []byte("\n"), nil }, nil, false, "no tags", true},
		{"malformed line", "0.1.0", "", lsRemoteOf(light("0.1.0", runSHA), "garbage"), nil, false, "not <id>TAB refs/tags/<name>", true},
		{"registry unreachable at step 1", "0.1.0", "", lsRemoteOf(light("0.1.0", runSHA)), func(s *latestSetup) { s.reg.errs[testRepo+":0.1.0"] = errors.New("dial tcp: connection refused") }, false, "connection refused", false},
		{"registry error at step 2", "0.1.0", "0.0.9", lsRemoteOf(light("0.1.0", runSHA)), func(s *latestSetup) { s.reg.errs[testRepo+":latest"] = errors.New("unauthorized") }, false, "unauthorized; refused", false},
		{"same version, other digest", "0.1.0", "", lsRemoteOf(light("0.1.0", runSHA)), func(s *latestSetup) {
			a := pushRow(s.reg.t, s.reg, testRepo, "amd64", "x", "0.1.0")
			b := pushRow(s.reg.t, s.reg, testRepo, "arm64", "y", "0.1.0")
			publishedIndex(s.reg.t, s.reg, testRepo, "0.1.0-other", a, b)
			var idx map[string]any
			_ = json.Unmarshal(s.reg.refs[testRepo+":0.1.0-other"], &idx)
			idx["annotations"] = map[string]string{versionKey: "0.1.0"}
			s.reg.refs[testRepo+":latest"] = mustJSON(s.reg.t, idx)
		}, false, "would not be forward", false},
		{"latest without the annotation", "0.2.0", "", lsRemoteOf(light("0.2.0", runSHA)), func(s *latestSetup) {
			var idx map[string]any
			_ = json.Unmarshal(s.reg.refs[testRepo+":0.2.0"], &idx)
			delete(idx, "annotations")
			s.reg.refs[testRepo+":latest"] = mustJSON(s.reg.t, idx)
		}, false, "is \"\", not X.Y.Z", false},
		{"a label that differs", "0.2.0", "0.1.0", lsRemoteOf(light("0.2.0", runSHA)), func(s *latestSetup) {
			for k := range s.reg.configs {
				if !strings.Contains(string(s.reg.configs[k]), "0.2.0") {
					s.reg.configs[k] = mustJSON(s.reg.t, map[string]any{"config": map[string]any{"Labels": map[string]string{versionKey: "0.0.1"}}})
					break
				}
			}
		}, false, "but the index annotation is", false},
		{"INDEX_DIGESTS is not X.Y.Z", "0.1.0", "", lsRemoteOf(light("0.1.0", runSHA)), func(s *latestSetup) {
			s.digests = `{"` + testRepo + `":"sha256:` + strings.Repeat("5", 64) + `"}`
		}, false, "has the content of", false},
		{"INDEX_DIGESTS of another image", "0.1.0", "", lsRemoteOf(light("0.1.0", runSHA)), func(s *latestSetup) {
			s.digests = `{"ghcr.io/other/x":"` + s.digest + `"}`
		}, false, "which is not a release image", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newLatestSetup(t, c.version, c.latest)
			if c.edit != nil {
				c.edit(&s)
				s.reg.calls = nil
			}
			done, f := moveLatest(c.version, s.digests, runSHA, latestDeps{reg: s.reg, repos: fixedRepos("postfix"), lsRemote: c.git})
			got := strings.Join(f, "\n")
			switch {
			case c.want == "" && len(f) > 0:
				t.Fatalf("findings %q", f)
			case c.want != "" && !strings.Contains(got, c.want):
				t.Fatalf("findings %q, want %q", f, c.want)
			case c.noRegistry && len(s.reg.calls) > 0:
				t.Fatalf("refused at step 0, but the registry was asked: %q", s.reg.calls)
			}
			if c.moves {
				want := [][]string{{"-t", testRepo + ":latest", testRepo + "@" + s.digest}}
				if !slices.EqualFunc(s.reg.creates, want, slices.Equal) || sha256Of(s.reg.refs[testRepo+":latest"]) != s.digest {
					t.Fatalf("create argv %q, want %q", s.reg.creates, want)
				}
				if len(done) != 1 || !strings.Contains(done[0], "moved to "+c.version) {
					t.Fatalf("done %q", done)
				}
			} else if len(s.reg.creates) != 0 {
				t.Fatalf("not moved, but create ran: %q", s.reg.creates)
			}
		})
	}
	t.Run("bad inputs", func(t *testing.T) {
		s := newLatestSetup(t, "0.1.0", "")
		deps := latestDeps{reg: s.reg, repos: fixedRepos("postfix"), lsRemote: lsRemoteOf(light("0.1.0", runSHA))}
		for _, in := range [][3]string{{"0.1", s.digests, runSHA}, {"0.1.0", s.digests, "HEAD"}, {"0.1.0", "nope", runSHA}} {
			if _, f := moveLatest(in[0], in[1], in[2], deps); len(f) == 0 || len(s.reg.creates) != 0 {
				t.Errorf("%q: findings %q, creates %q", in, f, s.reg.creates)
			}
		}
	})
}

// TestInspectError: only buildx's exact "ERROR: <ref>: not found" for the
// ref asked for is a missing ref (review B, N4).
func TestInspectError(t *testing.T) {
	const ref = testRepo + ":0.1.0"
	base := errors.New("exit status 1")
	for _, c := range []struct {
		ref, stderr string
		notFound    bool
	}{
		{ref, "ERROR: " + ref + ": not found\n", true},
		{ref, "ERROR: ghcr.io/keepia/mail-other:0.1.0: not found", false},
		{ref, "error getting credentials - err: exec: \"docker-credential-x\": executable file not found in $PATH", false},
		{ref, "WARNING: x\nERROR: " + ref + ": not found", false},
		{"", "ERROR: : not found", false},
	} {
		err := inspectError(c.ref, []string{"buildx"}, base, c.stderr)
		if errors.Is(err, errNotFound) != c.notFound {
			t.Errorf("%q: %v, want not found = %v", c.stderr, err, c.notFound)
		}
	}
}

// TestHighestTagNumeric: the comparison is numeric, field by field.
func TestHighestTagNumeric(t *testing.T) {
	out := []byte(strings.Join([]string{
		runSHA + "\trefs/tags/v0.9.9", otherSHA + "\trefs/tags/v0.10.0", tagObj + "\trefs/tags/v0.2.0",
		otherSHA + "\trefs/tags/v0.2.0^{}", runSHA + "\trefs/tags/v26.10-1", runSHA + "\trefs/tags/v1.0.0-rc1",
	}, "\n"))
	tag, commit, err := highestTag(out)
	if err != nil || tag != "v0.10.0" || commit != otherSHA {
		t.Fatalf("got %s %s %v", tag, commit, err)
	}
}

// TestLsRemoteCommand is step 0 with a fake git on PATH: the constant URL,
// an empty temp directory, only the three GIT_* settings and PATH (no
// inherited GIT_*, no HOME), and the timeout.
func TestLsRemoteCommand(t *testing.T) {
	bin := t.TempDir()
	record := filepath.Join(t.TempDir(), "record")
	script := "#!/bin/sh\n{ echo \"args:$*\"; echo \"pwd:$(pwd)\"; echo \"files:$(ls -A)\"; env; } >" + record + "\n" +
		"printf '%s\\trefs/tags/v0.1.0\\n' " + runSHA + "\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil { //nolint:gosec // the fake git must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GIT_DIR", "/nonexistent/keepia-git-dir")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'url.https://example.org/.insteadOf=https://github.com/'")
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	out, err := lsRemote()
	if err != nil || string(out) != runSHA+"\trefs/tags/v0.1.0\n" {
		t.Fatalf("out %q, err %v", out, err)
	}
	rec, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	r := string(rec)
	for _, w := range []string{"args:ls-remote --tags -- " + releaseRepoURL + "\n", "files:\n", "GIT_CONFIG_NOSYSTEM=1\n", "GIT_CONFIG_GLOBAL=/dev/null\n", "GIT_TERMINAL_PROMPT=0\n", "GIT_CEILING_DIRECTORIES=" + filepath.Clean(os.TempDir()) + "\n"} {
		if !strings.Contains(r, w) {
			t.Errorf("record lacks %q:\n%s", w, r)
		}
	}
	for _, bad := range []string{"GIT_DIR=", "GIT_CONFIG_PARAMETERS=", "\nHOME="} {
		if strings.Contains(r, bad) {
			t.Errorf("record has %q:\n%s", bad, r)
		}
	}
	wd, _ := os.Getwd()
	if strings.Contains(r, "pwd:"+wd+"\n") {
		t.Errorf("git ran in the working directory:\n%s", r)
	}
	// A git that does not answer: the timeout stops it.
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil { //nolint:gosec // the fake git must be executable
		t.Fatal(err)
	}
	old := lsRemoteTimeout
	lsRemoteTimeout = 200 * time.Millisecond
	defer func() { lsRemoteTimeout = old }()
	if _, err := lsRemote(); err == nil || !strings.Contains(err.Error(), "did not answer within") {
		t.Fatalf("err %v, want the timeout", err)
	}
}
