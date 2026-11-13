package main

import (
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Rule 7, the release surface (#27, plan revisions 1-5): the one workflow
// that may push packages, .github/workflows/release.yml (P1, rule 6 for
// every other file), has exactly the planned shape. The rule is the
// release policy as data: releaseJobs and the exact steps of the jobs
// that hold packages: write (and of push-rehearsal, their read-only
// twin). It reports:
//
//   - P2: a job that is not in the policy and a job of the policy that is
//     missing; permissions other than the policy's, top-level other than
//     {}; a job-level `uses:` (a reusable workflow).
//   - P3, P4, P5, P9: in push, push-rehearsal, index and latest, every
//     step is exactly the policy's step at that position (push-rehearsal
//     is push without the login, with the local registry service and a
//     host-network builder, #75): the same action
//     with exactly its inputs, or a run step whose trimmed text equals one
//     fixed line, with exactly its env and id and no if, shell,
//     working-directory or continue-on-error. Nothing is resolved: a text
//     is one of the lines or it is reported. So such a job runs no
//     repository script, make target or other `go run`, defines no shell
//     function and runs no eval, sh -c, source or xargs (P5 holds by
//     construction; its messages name the form), and pushes only through
//     the bake step (by digest under the bare repository, BAKE_SET
//     exactly the policy's lines, which build mode resolves) and
//     -publish-index and -move-latest.
//   - P6: `needs` and `if` of every job other than the policy's.
//   - P7: continue-on-error anywhere; a job container, services (except
//     push-rehearsal's exact registry service, #75),
//     concurrency, defaults or env (env only in the bake jobs, exactly
//     BAKE_TARGET, PLATFORM, VERSION and BAKE_SET); workflow env, defaults
//     other than run.shell bash; and in release, attest and attest-assets
//     any repository code (design-system's checkReleaseJob, ported).
//   - P8: `on:` other than workflow_dispatch with the inputs dry_run
//     (boolean, default true) and version (string, default ""); the
//     workflow-level concurrency other than exactly {group: release,
//     cancel-in-progress: false}, which serialises the runs that move
//     `latest` forward (B6); a `${{ }}` in any run text; a VERSION env
//     other than ${{ needs.version.outputs.version }}.
//   - SOURCE_DATE_EPOCH required in build, push and push-rehearsal before
//     the check step (B1 M3).
//   - Everywhere (#71, round 2): every env is a literal mapping, not an
//     expression; actions/setup-go has cache: false; the release modes,
//     docker login and docker/login-action appear only in the exact jobs;
//     the exact jobs' actions are at the policy's own commits
//     (actionPins).
//   - #27 part 4b: attest, attest-assets and release have exact steps too
//     (#71 review B, N2), so they run no third-party action, no `curl |
//     sh` and nothing that writes GITHUB_ENV; and in the other jobs
//     (#71 delta reviews A N1-N3, B D1-D2): a release mode in any
//     spelling (-flag=value, inside quotes or an sh -c text) and docker
//     login inside an sh -c text; action names compared without case;
//     actions/cache, a docker:// step and an anchore action anywhere; a
//     container run other than the build row's package-list line;
//     docker/setup-buildx-action other than with the policy's inputs
//     (the pinned BuildKit image, #71 review B, N6).
//
// The rule runs on release.yml in repository mode (make image-pins).

// releaseWorkflowName is the one workflow file name rule 6 exempts, in
// .github/workflows and in exactly this case.
const releaseWorkflowName = "release.yml"

const (
	versionExpr      = "${{ needs.version.outputs.version }}"
	releaseDryIf     = "${{ inputs.dry_run }}"
	releaseRealIf    = "${{ !inputs.dry_run }}"
	releaseBundleIf  = "${{ !cancelled() && needs.version.result == 'success' && needs.build.result == 'success' && ((inputs.dry_run && needs.push-rehearsal.result == 'success') || (!inputs.dry_run && needs.push.result == 'success' && needs.index.result == 'success')) }}"
	indexDigestsExpr = "${{ needs.index.outputs.digests }}"
	matrixRunsOn     = "${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}"
	plainRunsOn      = "ubuntu-24.04"

	// The fixed run lines of the jobs with packages: write (P4, numbered
	// as in the plan).
	lineEpoch        = `echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >>"$GITHUB_ENV"`
	lineLogin        = `echo "$TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin`
	lineCheck        = bakeCheckRun
	lineVerifyPushed = goRunPrefix + "go run ./tools/check-image-pins -verify-pushed"
	linePublishIndex = goRunPrefix + "go run ./tools/check-image-pins -publish-index"
	lineMoveLatest   = goRunPrefix + "go run ./tools/check-image-pins -move-latest"

	// syftRun starts the SBOM step of the build job (Q1: syft by a literal
	// version through the Go module proxy).
	syftRun = "go run github.com/anchore/syft/cmd/syft@v1.57.1 "

	// linePackages is the one container a job of release.yml runs: the
	// build row reads the package list of the verified image ID (plan
	// revision 2, D.7). Any other `docker run` is reported (#71 review A,
	// N2: `docker run anchore/syft:latest` would bypass the syft rule).
	linePackages = `docker run --rm --entrypoint cat "$VERIFIED_IMAGE" /usr/share/keepia/packages.txt >"$RUNNER_TEMP/tested/packages.txt"`

	// buildkitImage is the BuildKit image of every builder that
	// docker/setup-buildx-action starts (#71 review B, N6): the push
	// bake step hands it the GHCR credentials. It is the release of
	// moby/buildkit:buildx-stable-1 the runners used in #27 part 4a
	// (BuildKit v0.34.2), pinned by its index digest; bumped by hand, in
	// ci.yml, release.yml and here together.
	buildkitImage = "moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe"

	// registryImage is the throwaway registry push-rehearsal pushes to
	// (#75): CNCF distribution, Docker's official image, from mirror.gcr.io
	// (like ci.yml's postgres service), pinned by its index digest (amd64
	// and arm64); bumped by hand, in release.yml and here together.
	registryImage = "mirror.gcr.io/library/registry:3.1.2@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c"

	// rehearsalRegistry is where push-rehearsal pushes: its own registry
	// service on the runner's loopback (#75, D4: a fixed port, because a
	// job env cannot read the job context for a random one).
	rehearsalRegistry = "localhost:5000/keepia"

	// bakeRepoExpr is the repository name of a matrix row, mail or
	// mail-<image> (imageRepo without the registry); it reads only matrix.*
	// and format, as exprProblem allows.
	bakeRepoExpr = "${{ matrix.image == 'keepia' && 'mail' || format('mail-{0}', matrix.image) }}"
)

// rehearsalServices is push-rehearsal's exact `services` value (#75,
// maintainer decision 6850628924): the pinned registry, published on
// loopback only, with no env, options, credentials or volumes. Every other
// job of release.yml has no services.
var rehearsalServices = map[string]any{
	"registry": map[string]any{
		"image": registryImage,
		"ports": []any{"127.0.0.1:5000:5000"},
	},
}

// The exact run lines of attest, attest-assets and release (#71 review B,
// N2). They run no repository code: only sha256sum, jq and gh.
const (
	lineChecksum = "sha256sum -c SHA256SUMS"

	// lineSubjects names every attestation subject, checked: the index
	// digest of each image from the index job, and the platform manifest
	// digest of each image and architecture from the push rows' digest
	// files (the manifests -publish-index put into that index).
	lineSubjects = `for target in keepia postfix unbound olefy sogo; do
  repo=ghcr.io/keepia/mail-$target
  if [ "$target" = keepia ]; then
    repo=ghcr.io/keepia/mail
  fi
  index=$(jq -er --arg r "$repo" '.[$r]' <<<"$INDEX_DIGESTS")
  if [[ ! "$index" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::the index job names no index digest for $repo: '$index'"
    exit 1
  fi
  echo "$target=$index" >>"$GITHUB_OUTPUT"
  for arch in amd64 arm64; do
    manifest=$(jq -er --arg t "$target" --arg p "linux/$arch" --arg r "$repo" --arg v "$VERSION" \
      'select(.target == $t and .platform == $p and .repository == $r and .version == $v) | .manifest' \
      "$RUNNER_TEMP/digest/$target-$arch.json")
    if [[ ! "$manifest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      echo "::error::no platform manifest digest for $repo linux/$arch: '$manifest'"
      exit 1
    fi
    echo "$target-$arch=$manifest" >>"$GITHUB_OUTPUT"
  done
done`

	// lineCreateTag creates the tag on the built commit through the API
	// (design-system's release job). Creating a ref fails when it exists,
	// so a tag pushed since the version job's check is never reused. Before
	// it, no release of that tag may exist, a draft included (the version
	// job cannot see drafts with contents: read): so any draft the cleanup
	// step finds is this run's (#72 review B, N1).
	lineCreateTag = `if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "::error::not a release version: '$VERSION'"
  exit 1
fi
if out=$(gh release view "v$VERSION" --repo "$GITHUB_REPOSITORY" --json isDraft --jq .isDraft 2>&1); then
  echo "::error::a release v$VERSION exists (draft: $out); delete it if it is a leftover, then run again"
  exit 1
elif [ "$out" != "release not found" ]; then
  echo "::error::could not check for the release v$VERSION: $out"
  exit 1
fi
if ! gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" -f "ref=refs/tags/v$VERSION" -f "sha=$GITHUB_SHA" --silent; then
  echo "::error::could not create the tag v$VERSION on $GITHUB_SHA; does it exist?"
  exit 1
fi`

	// lineCreateRelease publishes the release on that tag (--verify-tag:
	// gh never creates one). The notes are the head from
	// release-notes.sh and the list generated from the pull requests
	// since BASE; the first release has no BASE and no --notes-start-tag
	// (plan revision 2, N9). gh fails if the release exists, so published
	// assets are never replaced. The assets are every file of dist, the
	// one SHA256SUMS covers (bundle checks that list), so `sha256sum -c
	// SHA256SUMS` passes on the downloaded assets (#72 review A, B1).
	lineCreateRelease = `start=()
if [ -n "$BASE" ]; then
  start=(--notes-start-tag "$BASE")
fi
gh release create "v$VERSION" --repo "$GITHUB_REPOSITORY" --verify-tag \
  --title "Keepia Mail $VERSION" --notes-file notes.md --generate-notes "${start[@]}" ./*`

	// lineRemoveTag removes the tag this run created, and the draft gh
	// leaves when an upload fails, so the next run can start over; also
	// when the job is cancelled or times out. A published release and its
	// tag stay.
	lineRemoveTag = `if out=$(gh release view "v$VERSION" --repo "$GITHUB_REPOSITORY" --json isDraft --jq .isDraft 2>&1); then
  if [ "$out" != true ]; then
    echo "::error::release v$VERSION is published although a step failed; check it, the tag stays"
    exit 1
  fi
  gh release delete "v$VERSION" --repo "$GITHUB_REPOSITORY" --yes
elif [ "$out" != "release not found" ]; then
  echo "::error::could not check for release v$VERSION: $out; delete the tag v$VERSION by hand if no release uses it"
  exit 1
fi
gh api --method DELETE "repos/$GITHUB_REPOSITORY/git/refs/tags/v$VERSION" --silent
echo "::notice::removed the tag v$VERSION; fix the failure and run the workflow again"`

	condRemoveTag = "(failure() || cancelled()) && steps.tag.outcome == 'success'"
)

// releaseJob is the policy of one job of release.yml.
type releaseJob struct {
	perms map[string]string
	needs []string
	cond  string // the exact `if`; "" for none
	// bake: build, push or push-rehearsal (job env exactly releaseBakeEnv).
	bake bool
	// steps: the exact steps (P4, P9); nil for a job checked otherwise.
	steps []stepSpec
	// outputs: the exact job outputs of a job with steps.
	outputs map[string]any
	// noRepoCode: release, attest and attest-assets (P7, design-system).
	noRepoCode bool
	// services: the exact job services (push-rehearsal only, #75); nil
	// for a job that has none (P7).
	services map[string]any
}

// stepSpec is one exact step: an action (uses, with) or a run step (run,
// env), with its id, and for a run step of release and attest* its
// working-directory and `if` (none in the jobs with the push path).
type stepSpec struct {
	uses string
	with map[string]any
	run  string
	env  map[string]any
	id   string
	wd   string
	cond string
}

// String names the spec; %#v keeps a string "false" apart from the
// boolean false (#71 review B, D3).
func (s stepSpec) String() string {
	if s.uses != "" {
		return fmt.Sprintf("uses %s@%s with %#v", s.uses, actionPins[s.uses], s.with)
	}
	out := fmt.Sprintf("run: %s (env %#v, id %q", s.run, s.env, s.id)
	if s.wd != "" {
		out += fmt.Sprintf(", working-directory %q", s.wd)
	}
	if s.cond != "" {
		out += fmt.Sprintf(", if %q", s.cond)
	}
	return out + ")"
}

// actionPins are the exact commits of the actions the exact jobs may use
// (#71 review B, N1): another commit of the same action, from a fork's
// network for example, is refused. They are CI's pins (ci.yml); a
// Dependabot bump of release.yml needs the same bump here.
var actionPins = map[string]string{
	"actions/checkout":           "3d3c42e5aac5ba805825da76410c181273ba90b1", // v7.0.1
	"actions/setup-go":           "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", // v7.0.0
	"docker/setup-buildx-action": "f87e5991a6d7451dcb8d9637bfbc97413f497069", // v4.4.1
	"actions/download-artifact":  "9000827ccba6bdab643e8b6fd33ac0654aef8333", // v8.0.2
	"actions/upload-artifact":    "cf430e030ddbb5b0abf93d22962f4752f3646cd9", // v7.0.2
	"docker/bake-action":         "59cb1203cd42bcefd40a1b6d73b589e48c86040e", // v7.5.0
	"actions/attest":             "1e69f48acb82d1966a394da916b4c1698aa569d6", // v4.2.2 (6843420864, Q2)
}

var (
	stepCheckout = stepSpec{uses: "actions/checkout", with: map[string]any{"persist-credentials": false}}
	// setup-go's cache is off (#71 review B, B1): it would restore main's
	// GOMODCACHE and GOCACHE, which any job on main can write, into the
	// jobs that run check-image-pins after docker login. Without it the
	// tool's modules come fresh from the proxy, checked against go.sum.
	stepSetupGo   = stepSpec{uses: "actions/setup-go", with: map[string]any{"go-version-file": "go.mod", "cache": false}}
	stepSetupBake = stepSpec{uses: "docker/setup-buildx-action", with: map[string]any{
		"driver-opts":             "image=" + buildkitImage,
		"buildkitd-config-inline": "[registry.\"docker.io\"]\n  mirrors = [\"mirror.gcr.io\"]",
	}}
	// stepSetupBakeHost is push-rehearsal's builder (#75): stepSetupBake
	// on the runner's host network, so BuildKit reaches the registry
	// service on loopback (BuildKit allows plain HTTP to localhost). Only
	// push-rehearsal has it; push keeps the bridge builder that holds the
	// GHCR credentials.
	stepSetupBakeHost = stepSpec{uses: "docker/setup-buildx-action", with: map[string]any{
		"driver-opts":             "image=" + buildkitImage + "\nnetwork=host",
		"buildkitd-config-inline": stepSetupBake.with["buildkitd-config-inline"],
	}}
	stepTested = stepSpec{uses: "actions/download-artifact", with: map[string]any{
		"name": "tested-${{ matrix.image }}-${{ matrix.arch }}", "path": "${{ runner.temp }}/tested",
	}}
	// The digest file of a push row; pushed.tar stays in the workspace and
	// never goes into an upload (R3).
	stepUploadDigest = stepSpec{uses: "actions/upload-artifact", with: map[string]any{
		"name": "digest-${{ matrix.image }}-${{ matrix.arch }}", "path": "${{ runner.temp }}/digest/", "if-no-files-found": "error",
	}}
	stepDigests = stepSpec{uses: "actions/download-artifact", with: map[string]any{
		"pattern": "digest-*", "path": "${{ runner.temp }}/digest", "merge-multiple": true,
	}}
	stepBake = stepSpec{uses: "docker/bake-action", id: bakeStepID, with: map[string]any{
		"source": ".", "targets": bakeTargetExpr, "set": bakeSetExpr,
	}}
	stepEpoch        = stepSpec{run: lineEpoch}
	stepLogin        = stepSpec{run: lineLogin, env: map[string]any{"TOKEN": "${{ secrets.GITHUB_TOKEN }}"}} //nolint:gosec // an expression the workflow must hold, not a credential
	stepCheck        = stepSpec{run: lineCheck}
	stepVerifyPushed = stepSpec{run: lineVerifyPushed, id: "pushed", env: map[string]any{"BAKE_METADATA": verifyEnvValue}}
	stepPublishIndex = stepSpec{run: linePublishIndex, id: "index", env: map[string]any{"VERSION": versionExpr}}
	stepMoveLatest   = stepSpec{run: lineMoveLatest, env: map[string]any{"VERSION": versionExpr, "INDEX_DIGESTS": indexDigestsExpr}}
)

// The steps of attest, attest-assets and release (#71 review B, N2).
var (
	stepDist     = stepSpec{uses: "actions/download-artifact", with: map[string]any{"name": "dist", "path": "dist"}}
	stepChecksum = stepSpec{run: lineChecksum, wd: "dist"}
	stepSubjects = stepSpec{run: lineSubjects, id: "subjects", env: map[string]any{"VERSION": versionExpr, "INDEX_DIGESTS": indexDigestsExpr}}
	// The release assets (the bundle, the SBOMs, the source lists, the
	// notes and SHA256SUMS), which the release job uploads.
	stepAttestAssets = stepSpec{uses: "actions/attest", with: map[string]any{"subject-path": "dist/*"}}
	ghToken          = "${{ github.token }}" //nolint:gosec // an expression the workflow must hold, not a credential
	stepCreateTag    = stepSpec{run: lineCreateTag, id: "tag", env: map[string]any{"GH_TOKEN": ghToken, "VERSION": versionExpr}}
	stepCreateRel    = stepSpec{run: lineCreateRelease, wd: "dist", env: map[string]any{
		"GH_TOKEN": ghToken, "VERSION": versionExpr, "BASE": "${{ needs.version.outputs.base }}",
	}}
	stepRemoveTag = stepSpec{run: lineRemoveTag, cond: condRemoveTag, env: map[string]any{"GH_TOKEN": ghToken, "VERSION": versionExpr}}
)

// releaseTargets are the own images in the order of bake's default group
// (the bundle job checks the set against bake itself).
var releaseTargets = []string{"keepia", "postfix", "unbound", "olefy", "sogo"}

// attestJobSteps are attest's steps: the release assets and the push
// rows' digest files, checked, the subjects, then per image the
// provenance of its index digest and the SBOM of each platform manifest
// (plan revision 2, F; push-to-registry stays off, so the job needs no
// packages: write).
func attestJobSteps() []stepSpec {
	steps := []stepSpec{stepDist, stepDigests, stepChecksum, stepSubjects}
	for _, t := range releaseTargets {
		repo := imageRepo(t)
		image := strings.TrimPrefix(repo, releaseRegistry+"/")
		steps = append(steps, stepSpec{uses: "actions/attest", with: map[string]any{
			"subject-name": repo, "subject-digest": "${{ steps.subjects.outputs." + t + " }}",
		}})
		for _, a := range releaseArchList {
			steps = append(steps, stepSpec{uses: "actions/attest", with: map[string]any{
				"subject-name":   repo,
				"subject-digest": "${{ steps.subjects.outputs." + t + "-" + a + " }}",
				"sbom-path":      "dist/sbom-" + image + "-" + a + ".spdx.json",
			}})
		}
	}
	return steps
}

var (
	pushSteps         = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepTested, stepEpoch, stepLogin, stepCheck, stepBake, stepVerifyPushed, stepUploadDigest}
	rehearsalSteps    = []stepSpec{stepCheckout, stepSetupGo, stepSetupBakeHost, stepTested, stepEpoch, stepCheck, stepBake, stepVerifyPushed, stepUploadDigest}
	indexSteps        = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepDigests, stepLogin, stepPublishIndex}
	latestSteps       = []stepSpec{stepCheckout, stepSetupGo, stepSetupBake, stepLogin, stepMoveLatest}
	attestSteps       = attestJobSteps()
	attestAssetsSteps = []stepSpec{stepDist, stepChecksum, stepAttestAssets}
	releaseJobSteps   = []stepSpec{stepDist, stepChecksum, stepCreateTag, stepCreateRel, stepRemoveTag}
)

var (
	readOnly    = map[string]string{"contents": "read"}
	readPackage = map[string]string{"contents": "read", "packages": "write"}
	attestPerms = map[string]string{"id-token": "write", "attestations": "write"}
)

// releaseJobOrder lists the jobs of the policy (P2: exactly these).
var releaseJobOrder = []string{"version", "build", "push-rehearsal", "push", "index", "bundle", "attest", "attest-assets", "release", "latest"}

var releaseJobs = map[string]releaseJob{
	"version":        {perms: map[string]string{"contents": "read", "pull-requests": "read"}},
	"build":          {perms: readOnly, needs: []string{"version"}, bake: true},
	"push-rehearsal": {perms: readOnly, needs: []string{"version", "build"}, cond: releaseDryIf, bake: true, steps: rehearsalSteps, services: rehearsalServices},
	"push":           {perms: readPackage, needs: []string{"version", "build"}, cond: releaseRealIf, bake: true, steps: pushSteps},
	"index": {perms: readPackage, needs: []string{"version", "push"}, cond: releaseRealIf, steps: indexSteps,
		outputs: map[string]any{"digests": "${{ steps.index.outputs.digests }}"}},
	"bundle":        {perms: readOnly, needs: []string{"version", "build", "push-rehearsal", "push", "index"}, cond: releaseBundleIf},
	"attest":        {perms: attestPerms, needs: []string{"version", "index", "bundle"}, cond: releaseRealIf, noRepoCode: true, steps: attestSteps},
	"attest-assets": {perms: attestPerms, needs: []string{"bundle"}, cond: releaseRealIf, noRepoCode: true, steps: attestAssetsSteps},
	"release": {perms: map[string]string{"contents": "write"}, needs: []string{"version", "bundle", "attest", "attest-assets"}, cond: releaseRealIf,
		noRepoCode: true, steps: releaseJobSteps},
	"latest": {perms: readPackage, needs: []string{"version", "index", "release"}, cond: releaseRealIf, steps: latestSteps},
}

// releaseBakeSet are the exact BAKE_SET lines of the bake jobs (revision
// 2 B, revision 3 B5): the release cache of the row, and for push and
// its twin the bare repository as the target's tags, the two outputs and
// the provenance attestation. Both push jobs push (push=true, #75): the
// rehearsal enters BuildKit's push path too, against its own registry
// service, so a push BuildKit refuses shows in a dry run. The tags are the
// bare repository because BuildKit refuses push-by-digest of a tagged
// name ("can't push tagged ref … by digest", run 43401448419); bake gives
// both outputs the tags as their name, so the tar and the registry hold
// the same index.
func releaseBakeSet(job string) []string {
	const t, scope = "${{ matrix.image }}", "release-${{ matrix.image }}-${{ matrix.arch }}"
	if job == "build" {
		return []string{t + ".cache-to=type=gha,mode=max,scope=" + scope}
	}
	registry := releaseRegistry
	if job == "push-rehearsal" {
		registry = rehearsalRegistry
	}
	return []string{
		t + ".cache-from=type=gha,scope=" + scope,
		t + ".tags=" + registry + "/" + bakeRepoExpr,
		t + ".output=type=image,push-by-digest=true,name-canonical=true,push=true",
		t + ".output=type=oci,dest=" + pushedTar,
		t + ".attest=type=provenance,mode=max",
	}
}

// releaseBakeEnv is the exact job env of a bake job, BAKE_SET aside.
var releaseBakeEnv = map[string]string{
	"BAKE_TARGET": "${{ matrix.image }}",
	"PLATFORM":    "linux/${{ matrix.arch }}",
	"VERSION":     versionExpr,
}

// releaseMatrix is the matrix of the bake jobs: every own image on both
// architectures (the bundle job checks the set against bake's default
// group).
var releaseArchs = []any{"amd64", "arm64"}

// releaseJobKeys are the job keys rule 7 allows; the ones it checks are
// below, the others cannot widen what a job runs.
var releaseJobKeys = map[string]bool{
	"name": true, "runs-on": true, "permissions": true, "needs": true, "if": true,
	"strategy": true, "env": true, "timeout-minutes": true, "steps": true, "outputs": true,
}

// releaseDeniedJobKeys get their own message (P2, P7). services is allowed
// only in a job whose policy has them (push-rehearsal), and then exactly.
var releaseDeniedJobKeys = map[string]string{
	"uses":              "a job of release.yml calls no reusable workflow",
	"container":         "a job of release.yml runs in no container",
	"services":          "only push-rehearsal has services: its registry",
	"concurrency":       "only the workflow-level concurrency group release serialises the runs (B6)",
	"defaults":          "only the workflow's defaults (run.shell: bash) apply",
	"continue-on-error": "a failed job must stop the release",
}

// releaseStepKeys are the step keys of the exact jobs: the spec fixes
// uses, with, run, env and id; no if, shell, working-directory or
// continue-on-error.
var releaseStepKeys = map[string]bool{"name": true, "uses": true, "with": true, "run": true, "env": true, "id": true, "timeout-minutes": true}

// releaseJobEnv are the step env keys of release, attest and
// attest-assets (design-system's RELEASE_JOB_ENV, with this repository's
// names).
var releaseJobEnv = map[string]bool{"GH_TOKEN": true, "TAG": true, "VERSION": true, "BASE": true, "INDEX_DIGESTS": true}

// Repository code in a run text (design-system's CODE_COMMAND, CODE_PATH
// and RELATIVE_COMMAND, without lookbehind and with this repository's
// tools and directories).
var (
	codeCommand     = regexp.MustCompile(`(?:^|[^\w./-])(node|nodejs|npm|npx|pnpm|yarn|corepack|python[\d.]*|pip[\d.]*|pipx|ruby|perl|deno|bun|go|make|gmake)(?:$|[^\w-])`)
	codePath        = regexp.MustCompile(`(?:^|[^\w-])((?:scripts|tools|cmd|internal|images|deploy|node_modules)/)`)
	relativeCommand = regexp.MustCompile("(?:^|[;&|(`{]|\\$\\()\\s*\\.{1,2}/")
	pinnedUses      = regexp.MustCompile(`^([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})$`)
)

// checkReleaseWorkflow applies rule 7 to release.yml's single document.
func checkReleaseWorkflow(top *yaml.Node, add func(int, string, ...any)) {
	var wf map[string]any
	if err := top.Decode(&wf); err != nil {
		add(top.Line, "release.yml does not decode: %v", err)
		return
	}
	keyLine := func(k string) int {
		if _, kn := mappingValue(top, k); kn != nil {
			return kn.Line
		}
		return top.Line
	}
	for _, k := range sortedKeys(wf) {
		switch k {
		case "name", "run-name", "on", "permissions", "concurrency", "defaults", "jobs":
		case "env":
			add(keyLine(k), "release.yml has no workflow env: it would reach every job, the ones with write tokens included (P7)")
		default:
			add(keyLine(k), "release.yml: workflow key %s is not in the release policy", k)
		}
	}
	checkReleaseOn(keyLine("on"), wf["on"], add)
	if p, ok := wf["permissions"]; !ok || !reflect.DeepEqual(p, map[string]any{}) {
		add(keyLine("permissions"), "release.yml: the top-level permissions must be exactly {}, so every job names its own (P2), got %v", p)
	}
	if c := wf["concurrency"]; !reflect.DeepEqual(c, map[string]any{"group": "release", "cancel-in-progress": false}) {
		add(keyLine("concurrency"), "release.yml: the workflow-level concurrency must be exactly {group: release, cancel-in-progress: false}: forward-only `latest` needs the runs serialised (P8, B6), got %v", c)
	}
	if d, ok := wf["defaults"]; !ok || !reflect.DeepEqual(d, map[string]any{"run": map[string]any{"shell": "bash"}}) {
		add(keyLine("defaults"), "release.yml: defaults must be exactly run.shell: bash (P7), got %v", d)
	}
	checkVersionEnv(keyLine("env"), "workflow", wf["env"], add)

	jobsNode, jobsKey := mappingValue(top, "jobs")
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		add(top.Line, "release.yml has no jobs mapping")
		return
	}
	seen := map[string]bool{}
	var buildJob map[string]any
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		name, val := jobsNode.Content[i], jobsNode.Content[i+1]
		var job map[string]any
		if err := val.Decode(&job); err != nil {
			add(name.Line, "job %s does not decode: %v", name.Value, err)
			continue
		}
		seen[name.Value] = true
		policy, ok := releaseJobs[name.Value]
		if !ok {
			add(name.Line, "job %s is not in the release policy (jobs: %s)", name.Value, strings.Join(releaseJobOrder, ", "))
			continue
		}
		if name.Value == "build" {
			buildJob = job
		}
		checkReleaseJob(name.Line, name.Value, policy, job, add)
	}
	for _, n := range releaseJobOrder {
		if !seen[n] {
			add(jobsKey.Line, "job %s of the release policy is missing", n)
		}
	}
	// push and push-rehearsal run the build job's matrix (P9).
	if buildJob != nil {
		for i := 0; i+1 < len(jobsNode.Content); i += 2 {
			name := jobsNode.Content[i]
			if name.Value != "push" && name.Value != "push-rehearsal" {
				continue
			}
			var job map[string]any
			if jobsNode.Content[i+1].Decode(&job) == nil && !reflect.DeepEqual(job["strategy"], buildJob["strategy"]) {
				add(name.Line, "job %s: strategy must equal the build job's, so every tested row is pushed (got %v, build has %v)", name.Value, job["strategy"], buildJob["strategy"])
			}
		}
	}
}

// checkReleaseOn checks P8's trigger: workflow_dispatch only, with the
// two inputs.
func checkReleaseOn(line int, on any, add func(int, string, ...any)) {
	m, ok := asMap(on)
	if !ok || len(m) != 1 {
		add(line, "release.yml: on: must be exactly workflow_dispatch (no push, schedule, workflow_call or workflow_run; P8), got %v", on)
		return
	}
	wd, ok := m["workflow_dispatch"]
	if !ok {
		add(line, "release.yml: on: must be exactly workflow_dispatch (P8), got %v", on)
		return
	}
	d, _ := asMap(wd)
	inputs, _ := asMap(d["inputs"])
	if len(d) != 1 || len(inputs) != 2 {
		add(line, "release.yml: workflow_dispatch must have exactly the inputs dry_run and version (P8), got %v", wd)
		return
	}
	check := func(name, typ string, def any) {
		in, ok := asMap(inputs[name])
		if !ok || in["type"] != typ || !reflect.DeepEqual(in["default"], def) {
			add(line, "release.yml: input %s must be type %s with default %#v (P8), got %v", name, typ, def, inputs[name])
			return
		}
		for _, k := range sortedKeys(in) {
			switch {
			case k == "type" || k == "default":
			case k == "description":
				if _, ok := in[k].(string); !ok {
					add(line, "release.yml: input %s: description is not a string", name)
				}
			case k == "required" && in[k] == false:
			default:
				add(line, "release.yml: input %s: key %s is not in the release policy", name, k)
			}
		}
	}
	check("dry_run", "boolean", true)
	check("version", "string", "")
}

// checkVersionEnv reports a VERSION env (any level) that is not exactly
// the version job's output (P8). An env that is not a mapping is reported
// by its caller at every level (the workflow env at all, a job env outside
// the bake jobs at all, a bake job's env and a step env as "not a
// mapping"), so it cannot hide a VERSION here.
func checkVersionEnv(line int, where string, env any, add func(int, string, ...any)) {
	m, _ := asMap(env)
	if v, ok := m["VERSION"]; ok && v != versionExpr {
		add(line, "release.yml: %s env VERSION must be exactly %s (P8), got %v", where, versionExpr, v)
	}
}

// checkReleaseJob checks one job against its policy.
func checkReleaseJob(line int, name string, p releaseJob, job map[string]any, add func(int, string, ...any)) {
	for _, k := range sortedKeys(job) {
		if k == "services" && p.services != nil {
			if !reflect.DeepEqual(job[k], p.services) {
				add(line, "job %s: services must be exactly %v (the pinned registry on loopback only, no env, options, credentials, volumes or other port; #75), got %v", name, p.services, job[k])
			}
			continue
		}
		if msg, ok := releaseDeniedJobKeys[k]; ok {
			add(line, "job %s: %s is not allowed: %s", name, k, msg)
		} else if !releaseJobKeys[k] {
			add(line, "job %s: key %s is not in the release policy", name, k)
		}
	}
	if _, has := job["services"]; p.services != nil && !has {
		add(line, "job %s: services must be exactly %v: the rehearsal pushes to its own registry (#75)", name, p.services)
	}
	want := map[string]any{}
	for k, v := range p.perms {
		want[k] = v
	}
	if !reflect.DeepEqual(job["permissions"], want) {
		add(line, "job %s: permissions must be exactly %v (P2), got %v", name, p.perms, job["permissions"])
	}
	if got := needsList(job["needs"]); !slices.Equal(got, sortedCopy(p.needs)) {
		add(line, "job %s: needs must be exactly %v, so a failed or skipped earlier job stops it (P6), got %v", name, p.needs, job["needs"])
	}
	cond, _ := job["if"].(string)
	if _, has := job["if"]; strings.TrimSpace(cond) != p.cond || (p.cond == "" && has) {
		want := p.cond
		if want == "" {
			want = "(none)"
		}
		add(line, "job %s: if must be exactly %s (P6), got %v", name, want, job["if"])
	}
	switch {
	case p.bake:
		checkReleaseBakeEnv(line, name, job["env"], add)
	case job["env"] != nil:
		add(line, "job %s: env is not allowed: only build, push and push-rehearsal have a job env (P7)", name)
	}
	if p.steps != nil {
		wantRunsOn := plainRunsOn
		if p.bake {
			wantRunsOn = matrixRunsOn
		}
		if job["runs-on"] != wantRunsOn {
			add(line, "job %s: runs-on must be exactly %s (a GitHub-hosted runner for a job with the push path), got %v", name, wantRunsOn, job["runs-on"])
		}
		if !p.bake && job["strategy"] != nil {
			add(line, "job %s: strategy is not allowed", name)
		}
		if !reflect.DeepEqual(job["outputs"], nilIfEmpty(p.outputs)) {
			add(line, "job %s: outputs must be exactly %v, got %v", name, p.outputs, job["outputs"])
		}
	}
	if name == "build" {
		checkReleaseMatrix(line, job["strategy"], add)
	}
	steps, ok := job["steps"].([]any)
	if !ok {
		add(line, "job %s has no steps list", name)
		return
	}
	checkReleaseSteps(line, name, p, steps, add)
}

// checkReleaseMatrix requires both architectures in the build job's
// matrix; push and push-rehearsal must have the same strategy.
func checkReleaseMatrix(line int, strategy any, add func(int, string, ...any)) {
	s, _ := asMap(strategy)
	m, _ := asMap(s["matrix"])
	images, _ := m["image"].([]any)
	if len(m) != 2 || !reflect.DeepEqual(m["arch"], releaseArchs) || len(images) == 0 || s["fail-fast"] != false {
		add(line, "job build: strategy must be fail-fast: false with exactly the matrix image (the own images) and arch [amd64, arm64], got %v", strategy)
	}
}

func nilIfEmpty(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	return m
}

func needsList(v any) []string {
	var out []string
	switch n := v.(type) {
	case string:
		out = []string{n}
	case []any:
		for _, e := range n {
			s, _ := e.(string)
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

// checkReleaseBakeEnv checks a bake job's env: exactly BAKE_TARGET,
// PLATFORM, VERSION and BAKE_SET, with exactly the policy's lines.
func checkReleaseBakeEnv(line int, name string, v any, add func(int, string, ...any)) {
	env, ok := asMap(v)
	if !ok {
		add(line, "job %s: the job env is not a mapping (%v): it must be exactly BAKE_TARGET, PLATFORM, VERSION and BAKE_SET", name, v)
		return
	}
	for _, k := range sortedKeys(env) {
		if _, ok := releaseBakeEnv[k]; !ok && k != "BAKE_SET" {
			add(line, "job %s: env %s is not in the release policy (BAKE_TARGET, PLATFORM, VERSION, BAKE_SET)", name, k)
		}
	}
	for _, k := range sortedBool(map[string]bool{"BAKE_TARGET": true, "PLATFORM": true, "VERSION": true}) {
		if env[k] != releaseBakeEnv[k] {
			add(line, "job %s: env %s must be exactly %s, got %v", name, k, releaseBakeEnv[k], env[k])
		}
	}
	s, _ := env["BAKE_SET"].(string)
	var got []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			got = append(got, l)
		}
	}
	want := releaseBakeSet(name)
	for _, l := range got {
		if !slices.Contains(want, l) {
			add(line, "job %s: BAKE_SET line %q is not in the release policy (P3; exactly: %s)", name, l, strings.Join(want, " | "))
		}
	}
	for _, l := range want {
		if !slices.Contains(got, l) {
			add(line, "job %s: BAKE_SET lacks the line %q (P3)", name, l)
		}
	}
	if !slices.Equal(got, want) && sameSet(got, want) {
		add(line, "job %s: BAKE_SET lines must be exactly, in this order: %s", name, strings.Join(want, " | "))
	}
}

// sameSet reports whether a and b hold the same lines (in any order or
// number).
func sameSet(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

// checkReleaseSteps checks the steps of a job: everywhere no
// continue-on-error, no ${{ }} in run, VERSION env exact; in the bake
// jobs SOURCE_DATE_EPOCH before the check step; in the exact jobs every
// step as the policy; in release, attest and attest-assets no repository
// code.
func checkReleaseSteps(line int, name string, p releaseJob, steps []any, add func(int, string, ...any)) {
	epochAt, checkAt := -1, -1
	for i, s := range steps {
		step, ok := asMap(s)
		if !ok {
			add(line, "job %s: step %d is not a mapping", name, i+1)
			continue
		}
		if _, ok := step["continue-on-error"]; ok {
			add(line, "job %s: step %d has continue-on-error: a failed step must stop the release (P7)", name, i+1)
		}
		// An env given as one expression (`env: ${{ fromJSON(…) }}`) would
		// set any variable, BASH_ENV included, past every env rule below,
		// which read env as a mapping (#71 review A, B1).
		if e, has := step["env"]; has {
			if _, ok := asMap(e); !ok {
				add(line, "job %s: step %d: env is not a mapping (%v): every env of release.yml is a literal mapping (P4, P7)", name, i+1, e)
			}
		}
		run, _ := step["run"].(string)
		if strings.Contains(run, "${{") {
			add(line, "job %s: step %d has ${{ }} in its run text: inputs, outputs and tokens reach a step only through env (P8)", name, i+1)
		}
		checkVersionEnv(line, fmt.Sprintf("job %s step %d", name, i+1), step["env"], add)
		switch strings.TrimSpace(run) {
		case lineEpoch:
			if epochAt < 0 {
				epochAt = i
			}
		case lineCheck:
			checkAt = i
		}
		if p.noRepoCode {
			checkNoRepoCode(line, name, i, step, add)
		}
		if runsSyft(run) && (!strings.HasPrefix(strings.TrimSpace(run), syftRun) || strings.Count(run, "anchore/syft") != 1 ||
			!reflect.DeepEqual(asAnyMap(step["env"]), map[string]any{"SYFT_CHECK_FOR_APP_UPDATE": "false"})) {
			add(line, "job %s: step %d runs syft other than as `%s…` with exactly the env SYFT_CHECK_FOR_APP_UPDATE: \"false\" (a literal version through the Go module proxy, no update check; plan revision 2 D.7)", name, i+1, syftRun)
		}
		checkReleaseUses(line, name, i, step, add)
		if p.steps == nil {
			checkReleaseModesElsewhere(line, name, i, step, add)
			checkContainerRuns(line, name, i, run, add)
		}
		// Action names without case: GitHub resolves owner and repository
		// that way (#71 delta reviews A N3, B D1).
		uses, _ := step["uses"].(string)
		action, _, _ := strings.Cut(strings.ToLower(uses), "@")
		if p.steps == nil && action == "actions/setup-go" {
			if w, _ := asMap(step["with"]); w["cache"] != false {
				add(line, "job %s: step %d uses actions/setup-go without cache: false: it would restore a Go cache that other jobs on main write (#71 review B, B1)", name, i+1)
			}
		}
		if p.steps == nil && action == "docker/setup-buildx-action" && !sameInputs(step["with"], stepSetupBake.with) {
			add(line, "job %s: step %d uses docker/setup-buildx-action with %#v; release.yml has exactly %#v: CI's mirror and the pinned BuildKit image (#71 review B, N6)", name, i+1, step["with"], stepSetupBake.with)
		}
	}
	if p.bake && (epochAt < 0 || checkAt < 0 || epochAt > checkAt) {
		add(line, "job %s: the step `run: %s` is required before the check step: without it a full cache hit still gives another config (B1 M3)", name, lineEpoch)
	}
	if p.steps != nil {
		checkExactSteps(line, name, p.steps, steps, add)
	}
}

// runsSyft reports whether a run text runs syft: a command whose word is
// syft (any path), or a `go run` (or `go install`) of a package under
// anchore/syft. A word that only names syft (release-sources' -syft
// FILE) does not count (#71 review A, B2).
func runsSyft(text string) bool {
	for _, words := range shellCommands(text) {
		words = dropRedirects(words)
		i := commandStart(words)
		if i >= len(words) {
			continue
		}
		if path0(words[i]) == "syft" {
			return true
		}
		if path0(words[i]) == "go" && i+1 < len(words) && (words[i+1] == "run" || words[i+1] == "install") {
			for _, a := range words[i+2:] {
				if strings.Contains(a, "anchore/syft") {
					return true
				}
			}
		}
	}
	return false
}

// releaseModeFlags are the tool modes only the exact jobs run.
var releaseModeFlags = []string{"-verify-pushed", "-publish-index", "-move-latest"}

// checkReleaseModesElsewhere reports, in a job that is not an exact-steps
// job, a step that runs a release mode of the tool or logs in to a
// registry (#71 review A, B3): those belong to push, push-rehearsal,
// index and latest only. A mode counts in any spelling (#71 delta
// reviews A N1, B D2): its name anywhere in the text once quotes and
// backslashes are gone, so -move-latest=true, --publish-index, "-verify-"pushed
// and a mode inside a `bash -c '…'` text are reported. docker login
// counts wherever its words appear in a command, an sh -c text
// included.
func checkReleaseModesElsewhere(line int, name string, i int, step map[string]any, add func(int, string, ...any)) {
	run, _ := step["run"].(string)
	flat := normalizeShell(run)
	for _, f := range releaseModeFlags {
		if strings.Contains(flat, strings.TrimLeft(f, "-")) {
			add(line, "job %s: step %d runs %s: the release modes run only in push, push-rehearsal, index and latest", name, i+1, f)
		}
	}
	login := false
	for _, words := range commands(run) {
		for j, w := range words {
			if engines[path0(w)] {
				if sub, _ := subcommand(words[j+1:]); sub == "login" {
					login = true
				}
			}
		}
	}
	if login {
		add(line, "job %s: step %d runs docker login: only push, index and latest log in to GHCR", name, i+1)
	}
	if uses, _ := step["uses"].(string); strings.HasPrefix(strings.ToLower(uses), "docker/login-action@") {
		add(line, "job %s: step %d uses docker/login-action: only push, index and latest log in to GHCR", name, i+1)
	}
}

// checkReleaseUses reports, in every job of release.yml, an action that
// could bring in code or a cache the rule does not see (#71 delta review
// A N2, N3): actions/cache (and its restore and save actions), which
// would restore a module or build cache that any job on main can write;
// a `docker://` step, which runs an image; and any anchore action
// (sbom-action, scan-action), which runs syft or grype in a version the
// syft rule does not fix.
func checkReleaseUses(line int, name string, i int, step map[string]any, add func(int, string, ...any)) {
	uses, _ := step["uses"].(string)
	u := strings.ToLower(strings.TrimSpace(uses))
	action, _, _ := strings.Cut(u, "@")
	switch {
	case action == "actions/cache" || strings.HasPrefix(action, "actions/cache/"):
		add(line, "job %s: step %d uses %s: release.yml restores and saves no cache, so no step reads what another job on main wrote (#71 review A, N3)", name, i+1, uses)
	case strings.HasPrefix(u, "docker://"):
		add(line, "job %s: step %d uses %s: a step of release.yml runs no image", name, i+1, uses)
	case strings.HasPrefix(action, "anchore/"):
		add(line, "job %s: step %d uses %s: syft runs only as `%s…` (#71 review A, N2)", name, i+1, uses, syftRun)
	}
}

// checkContainerRuns reports, in a job that is not an exact-steps job, a
// container the step runs (docker, podman or nerdctl run or create, also
// as `container run`) unless the step's text is exactly linePackages:
// `docker run anchore/syft:latest …` would bypass the syft rule, and any
// other image would run unpinned (#71 review A, N2).
func checkContainerRuns(line int, name string, i int, run string, add func(int, string, ...any)) {
	if strings.TrimSpace(run) == linePackages {
		return
	}
	for _, words := range commands(run) {
		for j, w := range words {
			if !engines[path0(w)] {
				continue
			}
			sub, after := subcommand(words[j+1:])
			if sub == "container" {
				sub, _ = subcommand(after)
			}
			if sub == "run" || sub == "create" {
				add(line, "job %s: step %d runs a container (%s %s): in release.yml only the build row's package-list line does, of the verified image (`%s`)", name, i+1, path0(w), sub, linePackages)
				return
			}
		}
	}
}

// checkNoRepoCode is design-system's checkReleaseJob for one step: no
// checkout, no local action, no shell, step env only from releaseJobEnv,
// and no repository or dependency code in a run text.
func checkNoRepoCode(line int, name string, i int, step map[string]any, add func(int, string, ...any)) {
	where := fmt.Sprintf("job %s: step %d", name, i+1)
	uses, _ := step["uses"].(string)
	if strings.HasPrefix(strings.ToLower(uses), "actions/checkout@") {
		add(line, "%s checks out the repository (%s): this job runs no repository code (P7)", where, uses)
	}
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		add(line, "%s uses the local action %s: this job runs no repository code (P7)", where, uses)
	}
	if _, ok := step["shell"]; ok {
		add(line, "%s sets a shell: only the workflow default bash (P7)", where)
	}
	if _, ok := step["working-directory"]; ok {
		// A working directory is harmless without a checkout, but the
		// download path is fixed; keep the steps plain.
		wd, _ := step["working-directory"].(string)
		if strings.Contains(wd, "${{") {
			add(line, "%s: working-directory has an expression", where)
		}
	}
	// An env that is not a mapping is reported for every step by
	// checkReleaseSteps; here only its keys are checked.
	env, _ := asMap(step["env"])
	for _, k := range sortedKeys(env) {
		if !releaseJobEnv[k] {
			add(line, "%s: step env %s is not one of %s (P7)", where, k, strings.Join(sortedBool(releaseJobEnv), ", "))
		}
	}
	run, _ := step["run"].(string)
	var code []string
	for _, l := range strings.Split(run, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			code = append(code, l)
		}
	}
	text := strings.Join(code, "\n")
	if m := codeCommand.FindStringSubmatch(text); m != nil {
		add(line, "%s runs repository or dependency code (%s): this job runs no repository code (P7)", where, m[1])
	} else if m := codePath.FindStringSubmatch(text); m != nil {
		add(line, "%s runs repository or dependency code (%s): this job runs no repository code (P7)", where, m[1])
	}
	for _, l := range code {
		if relativeCommand.MatchString(l) {
			add(line, "%s runs a repository-relative command: this job runs no repository code (P7)", where)
			break
		}
	}
}

// checkExactSteps holds a job to its exact steps (P3, P4, P5, P9). Each
// step is checked on its own first (what it runs or uses must be allowed
// in this job at all), then, when the count matches, against the policy's
// step at its position.
func checkExactSteps(line int, name string, want []stepSpec, steps []any, add func(int, string, ...any)) {
	runs := map[string]bool{}
	actions := map[string]bool{}
	// if and working-directory only where a step of the policy has them
	// (release's cleanup step and the checksum steps; stepDiff compares
	// them exactly).
	keys := maps.Clone(releaseStepKeys)
	for _, s := range want {
		if s.run != "" {
			runs[s.run] = true
		} else {
			actions[s.uses] = true
		}
		if s.cond != "" {
			keys["if"] = true
		}
		if s.wd != "" {
			keys["working-directory"] = true
		}
	}
	// The P3/P5 messages name the forms a job with the push path (push,
	// its twin, index, latest) must not run; attest* and release have
	// their own messages (checkNoRepoCode).
	writes := !releaseJobs[name].noRepoCode
	ownProblem := make([]bool, len(steps))
	for i, s := range steps {
		step, _ := asMap(s)
		for _, k := range sortedKeys(step) {
			if !keys[k] {
				add(line, "job %s: step %d has %s: a step of this job has no if, shell, working-directory or continue-on-error other than the policy's (P4)", name, i+1, k)
				ownProblem[i] = true
			}
		}
		uses, hasUses := step["uses"].(string)
		run, hasRun := step["run"].(string)
		switch {
		case hasUses && hasRun:
			add(line, "job %s: step %d has both uses and run", name, i+1)
			ownProblem[i] = true
		case hasUses:
			m := pinnedUses.FindStringSubmatch(uses)
			switch {
			case m == nil || !actions[m[1]]:
				add(line, "job %s: step %d uses %s, which is not one of this job's actions (P9: %s, each pinned to a commit)", name, i+1, uses, strings.Join(sortedBool(actions), ", "))
				ownProblem[i] = true
			case m[2] != actionPins[m[1]]:
				add(line, "job %s: step %d uses %s at %s, not at the policy's pin %s (P9)", name, i+1, m[1], m[2], actionPins[m[1]])
				ownProblem[i] = true
			}
		case hasRun:
			t := strings.TrimSpace(run)
			if !runs[t] {
				add(line, "job %s: step %d runs a text that is not one of this job's lines; nothing is resolved, the text must equal a line exactly (P4): %q", name, i+1, t)
				ownProblem[i] = true
				if writes {
					for _, msg := range pushJobTextProblems(t) {
						add(line, "job %s: step %d %s", name, i+1, msg)
					}
				}
			}
		default:
			add(line, "job %s: step %d has neither uses nor run", name, i+1)
			ownProblem[i] = true
		}
	}
	if len(steps) != len(want) {
		var list []string
		for _, s := range want {
			if s.run != "" {
				first, _, more := strings.Cut(s.run, "\n")
				if more {
					first += " …"
				}
				list = append(list, "run: "+first)
			} else {
				list = append(list, s.uses)
			}
		}
		add(line, "job %s has %d steps; the release policy has exactly %d, in this order: %s", name, len(steps), len(want), strings.Join(list, " | "))
		return
	}
	for i, s := range steps {
		if ownProblem[i] {
			continue
		}
		step, _ := asMap(s)
		if d := stepDiff(want[i], step); d != "" {
			add(line, "job %s: step %d must be exactly %s: %s", name, i+1, want[i], d)
		}
	}
}

// stepDiff says how a step differs from its spec ("" if it does not).
func stepDiff(want stepSpec, step map[string]any) string {
	id, _ := step["id"].(string)
	if id != want.id {
		return fmt.Sprintf("id %q, want %q", id, want.id)
	}
	if want.uses != "" {
		m := pinnedUses.FindStringSubmatch(fmt.Sprint(step["uses"]))
		if m == nil || m[1] != want.uses || m[2] != actionPins[want.uses] {
			return fmt.Sprintf("uses %v", step["uses"])
		}
		if !sameInputs(step["with"], want.with) {
			return fmt.Sprintf("with %#v", step["with"])
		}
		if _, has := step["env"]; has {
			return "an action step has no env"
		}
		for _, k := range []string{"if", "working-directory"} {
			if _, has := step[k]; has {
				return "an action step has no " + k
			}
		}
		return ""
	}
	if strings.TrimSpace(fmt.Sprint(step["run"])) != want.run {
		return fmt.Sprintf("run %q", step["run"])
	}
	if _, has := step["with"]; has {
		return "a run step has no with"
	}
	for _, k := range []struct{ key, want string }{{"working-directory", want.wd}, {"if", want.cond}} {
		v, has := step[k.key]
		s, _ := v.(string)
		if has != (k.want != "") || strings.TrimSpace(s) != k.want {
			return fmt.Sprintf("%s %#v, want %q", k.key, v, k.want)
		}
	}
	// The env key itself, not its decoded mapping: an env given as one
	// expression is not "no env" (#71 review A, B1).
	env, has := step["env"]
	switch m, ok := asMap(env); {
	case len(want.env) == 0 && has:
		return fmt.Sprintf("env %v, want none", env)
	case len(want.env) > 0 && (!ok || !reflect.DeepEqual(m, want.env)):
		return fmt.Sprintf("env %v", env)
	}
	return ""
}

func asAnyMap(v any) map[string]any {
	m, _ := asMap(v)
	return m
}

// sameInputs compares action inputs; a string input matches without its
// trailing newline (a `|` block scalar).
func sameInputs(got any, want map[string]any) bool {
	g, ok := asMap(got)
	if !ok || len(g) != len(want) {
		return false
	}
	for k, w := range want {
		v := g[k]
		if ws, ok := w.(string); ok {
			s, ok := v.(string)
			if !ok || strings.TrimRight(s, "\n") != ws {
				return false
			}
			continue
		}
		if !reflect.DeepEqual(v, w) {
			return false
		}
	}
	return true
}

// pushJobTextProblems names, for a run text of a job with the push path
// that is not one of its lines, the forms P3 and P5 forbid: a shell
// function, eval, sh -c, source and xargs, and every other way to push
// or reach a registry or API.
func pushJobTextProblems(text string) []string {
	var out []string
	if shellFunction.MatchString(text) {
		out = append(out, "defines a shell function: a job with packages: write defines no shell function (P5)")
	}
	seen := map[string]bool{}
	for _, words := range shellCommands(text) {
		words = dropRedirects(words)
		i := commandStart(words)
		if i >= len(words) {
			continue
		}
		w := path0(words[i])
		form := ""
		switch {
		case w == "eval" || w == "source" || w == "." || w == "xargs":
			form = w
		case interpreters[w].shell:
			for _, a := range words[i+1:] {
				if a == "-c" || (len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.HasSuffix(a, "c")) {
					form = w + " -c"
				}
			}
		}
		if form != "" && !seen[form] {
			seen[form] = true
			out = append(out, fmt.Sprintf("runs %s: a job with packages: write runs no eval, sh -c, source or xargs (P5)", form))
		}
	}
	uses := imageUses(text)
	for _, words := range commands(text) {
		for _, w := range words {
			switch path0(w) {
			case "oras", "regctl", "curl", "wget":
				uses = append(uses, path0(w))
			case "gh":
				uses = append(uses, "gh")
			}
		}
	}
	for _, u := range uses {
		if !seen[u] {
			seen[u] = true
			out = append(out, fmt.Sprintf("runs %s: an image leaves a job with packages: write only through the checked bake step, -publish-index and -move-latest (P3)", u))
		}
	}
	return out
}

func path0(w string) string {
	return w[strings.LastIndex(w, "/")+1:]
}

// pushJobScripts are the repository scripts a job with packages: write
// may run: none (6836353945's allowlist is empty, plan revision 2 P4).
// checkPushJobScript is what an entry would have to pass.
var pushJobScripts = map[string]bool{}

// checkPushJobScript checks a script on pushJobScripts (P5): no function
// that runs its positional parameters (forwardingFunctions, by name), and
// no eval, sh -c, source or xargs.
func checkPushJobScript(src []byte) []string {
	text := string(src)
	top, funcs := splitFunctions(text)
	var out []string
	fwd := forwardingFunctions(funcs, literalCommands(text), nil)
	for _, n := range sortedBool(fwd) {
		out = append(out, fmt.Sprintf("function %s runs its arguments as a command: a script a job with packages: write runs has no forwarding function (P5)", n))
	}
	for _, f := range append([]string{top}, funcBodies(funcs)...) {
		for _, msg := range pushJobTextProblems(f) {
			if strings.Contains(msg, "(P5)") && !strings.Contains(msg, "shell function") && !slices.Contains(out, msg) {
				out = append(out, msg)
			}
		}
	}
	return out
}

func funcBodies(funcs []shellFunc) []string {
	var out []string
	for _, f := range funcs {
		out = append(out, f.body)
	}
	return out
}
