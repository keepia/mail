package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// Build mode for release.yml (rule 5 in release.yml, #27). A build whose
// --set lines name a release- cache scope is a release build, and its
// resolved target must have exactly one of two shapes:
//
//   - the build job (tested, loaded): cache-to type=gha,mode=max with the
//     row's release-<target>-<arch> scope, no cache-from, no output and no
//     attest;
//   - the push and push-rehearsal jobs: cache-from type=gha with that
//     scope, no cache-to, exactly the two outputs
//     type=image,push-by-digest=true,name-canonical=true,push=true|false
//     and type=oci,dest=pushed.tar, and exactly the attestation
//     type=provenance,mode=max (BuildKit's built-in generator; no
//     generator image).
//
// In both, VERSION (the job env) is X.Y.Z, REGISTRY is not set, and the
// target's tags are exactly ghcr.io/keepia/mail[-<target>]:<VERSION>:
// with push-by-digest the tags name the repository the image goes to
// (buildx replaces the output's name with them, so the output has no
// name=). The workflow side (release.go) holds each job to its exact
// BAKE_SET lines; this side checks what they resolve to.

// releaseRegistry is the registry prefix of every released image.
const releaseRegistry = "ghcr.io/keepia"

// pushedTar is the OCI layout tar the push bake step writes in the
// workspace, next to the registry push (the review's B5: bake writes
// only inside its working directory without an entitlement).
const pushedTar = "pushed.tar"

// semverRE is X.Y.Z without a v, leading zeros or a suffix.
var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// releaseBuild is what a release build is checked against.
type releaseBuild struct {
	version string
}

// releaseTargetKeys are the resolved keys a release build may have on top
// of targetKeys; checkReleaseTarget checks their values exactly.
var releaseTargetKeys = map[string]bool{"output": true, "attest": true}

// releaseBuildOf returns the release policy when the build's --set lines
// name a release- cache scope (nil otherwise), and its problems: VERSION
// must be X.Y.Z and REGISTRY unset.
func releaseBuildOf(sets []string) (*releaseBuild, []string) {
	release := false
	for _, s := range sets {
		if strings.Contains(s, "scope=release-") {
			release = true
		}
	}
	if !release {
		return nil, nil
	}
	var problems []string
	v := os.Getenv("VERSION")
	if !semverRE.MatchString(v) {
		problems = append(problems, fmt.Sprintf("a release build needs VERSION as X.Y.Z (the job env ${{ needs.version.outputs.version }}), got %q", v))
	}
	if r, ok := os.LookupEnv("REGISTRY"); ok {
		problems = append(problems, fmt.Sprintf("a release build takes the default REGISTRY (%s); REGISTRY=%q is set", releaseRegistry, r))
	}
	return &releaseBuild{version: v}, problems
}

// imageRepo is the repository a target is released to:
// ghcr.io/keepia/mail for keepia, ghcr.io/keepia/mail-<target> otherwise.
func imageRepo(target string) string {
	if target == "keepia" {
		return releaseRegistry + "/mail"
	}
	return releaseRegistry + "/mail-" + target
}

// checkReleaseTarget checks a resolved target of a release build.
func checkReleaseTarget(bad func(string, ...any), name string, t bakeTarget, policy targetPolicy) {
	want := []string{imageRepo(name) + ":" + policy.release.version}
	if !reflect.DeepEqual(t.Tags, want) {
		bad("a release build's tags must be exactly %v (they name the repository the image is pushed to), got %v", want, t.Tags)
	}
	scope := policy.cacheScope
	gha := func(mode bool) []map[string]string {
		e := map[string]string{"type": "gha", "scope": scope}
		if mode {
			e["mode"] = "max"
		}
		return []map[string]string{e}
	}
	exact := func(attr string, got, want []map[string]string) {
		if len(got) == 0 && len(want) == 0 {
			return
		}
		if !reflect.DeepEqual(got, want) {
			bad("a release build's %s must be exactly %v, got %v", attr, want, got)
		}
	}
	if len(t.Output) == 0 && len(t.Attest) == 0 {
		// The build job: tested and loaded, writes the release cache.
		exact("cache-from", t.CacheFrom, nil)
		exact("cache-to", t.CacheTo, gha(true))
		return
	}
	// push and push-rehearsal: every layer from the build job's cache.
	exact("cache-from", t.CacheFrom, gha(false))
	exact("cache-to", t.CacheTo, nil)
	if len(t.Output) != 2 || len(t.Output[0]) != 4 || t.Output[0]["type"] != "image" ||
		t.Output[0]["push-by-digest"] != "true" || t.Output[0]["name-canonical"] != "true" ||
		(t.Output[0]["push"] != "true" && t.Output[0]["push"] != "false") ||
		!reflect.DeepEqual(t.Output[1], map[string]string{"type": "oci", "dest": pushedTar}) {
		bad("a release build's output must be exactly [type=image,push-by-digest=true,name-canonical=true,push=true|false type=oci,dest=%s], got %v", pushedTar, t.Output)
	}
	exact("attest", t.Attest, []map[string]string{{"type": "provenance", "mode": "max"}})
}

// pushedTarProblem reports a pushed.tar that exists in root before the
// build, in any form (file, directory, symlink, also a committed one):
// bake would write through it.
func pushedTarProblem(root string) string {
	p := filepath.Join(root, pushedTar)
	_, err := os.Lstat(p)
	switch {
	case err == nil:
		return fmt.Sprintf("%s exists before the build (a file, directory or symlink): the push step's OCI output would be written through it; nothing may create it before the bake step", p)
	case !os.IsNotExist(err):
		return fmt.Sprintf("%s cannot be checked: %v", p, err)
	}
	return ""
}
