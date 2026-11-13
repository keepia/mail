package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release fixture: the repository's own .github/workflows/release.yml
// (#27 part 4b; part 4a had a copy of the planned shape here), in the
// tree testdata/repos/pass-27-release (its Dockerfile and the scripts its
// build job runs). TestReleaseWorkflow checks it is clean there;
// TestReleaseSurface runs each fail-27-* case on a copy with one change,
// so every red fixture is a change to the workflow that runs.

const (
	releaseFixtureDir = "testdata/repos/pass-27-release"
	releaseWorkflow   = "../../.github/workflows/release.yml"
)

func releaseFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(releaseWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestReleaseWorkflow: the repository's release.yml is clean in the
// fixture tree (make image-pins checks it in the repository itself).
func TestReleaseWorkflow(t *testing.T) {
	root := t.TempDir()
	copyTree(t, releaseFixtureDir, root)
	write(t, root, ".github/workflows/release.yml", releaseFixture(t))
	var out, errOut bytes.Buffer
	if code := run([]string{root}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, want 0:\n%s%s", code, out.String(), errOut.String())
	}
}

// jobBlock returns the start and end of a job's block in the fixture.
var jobStart = regexp.MustCompile(`(?m)^  [a-z][a-z-]*:\n`)

func jobBlock(t *testing.T, wf, job string) (int, int) {
	t.Helper()
	start := strings.Index(wf, "\n  "+job+":\n")
	if start < 0 {
		t.Fatalf("no job %s in the fixture", job)
	}
	start++
	end := len(wf)
	if loc := jobStart.FindStringIndex(wf[start+1:]); loc != nil {
		end = start + 1 + loc[0]
	}
	return start, end
}

// mutation changes the fixture's release.yml.
type mutation func(t *testing.T, wf string) string

// inJob replaces old (which must occur in the job's block) by new, once.
func inJob(job, old, new string) mutation {
	return func(t *testing.T, wf string) string {
		s, e := jobBlock(t, wf, job)
		block := wf[s:e]
		if !strings.Contains(block, old) {
			t.Fatalf("job %s has no %q", job, old)
		}
		return wf[:s] + strings.Replace(block, old, new, 1) + wf[e:]
	}
}

// inWorkflow replaces old, which must occur exactly once, by new.
func inWorkflow(old, new string) mutation {
	return func(t *testing.T, wf string) string {
		if n := strings.Count(wf, old); n != 1 {
			t.Fatalf("%q occurs %d times in the fixture, want 1", old, n)
		}
		return strings.Replace(wf, old, new, 1)
	}
}

func dropJob(job string) mutation {
	return func(t *testing.T, wf string) string {
		s, e := jobBlock(t, wf, job)
		return wf[:s] + wf[e:]
	}
}

func appendText(text string) mutation {
	return func(_ *testing.T, wf string) string { return wf + text }
}

func unchanged(_ *testing.T, wf string) string { return wf }

const (
	pushOutputTrue  = "${{ matrix.image }}.output=type=image,push-by-digest=true,name-canonical=true,push=true\n"
	pushOutputFalse = "${{ matrix.image }}.output=type=image,push-by-digest=true,name-canonical=true,push=false\n"
	ociOutput       = "${{ matrix.image }}.output=type=oci,dest=pushed.tar\n"
	attestLine      = "${{ matrix.image }}.attest=type=provenance,mode=max\n"
	pushedStep      = "      - id: pushed\n"
	sha40           = "1111111111111111111111111111111111111111"
)

// runStep is a run step inserted before the -verify-pushed step.
func runStepBefore(job, run string) mutation {
	return inJob(job, pushedStep, "      - run: "+run+"\n"+pushedStep)
}

// releaseCases are the red fixtures of rule 7 (test 18), one change each
// to pass-27-release, with the findings each must give: every fragment
// in want, and exactly that many findings. The plan point is in the name.
var releaseCases = []struct {
	name   string
	mutate mutation
	extra  map[string]string // other files of the tree
	want   []string
}{
	// P1: the exemption is the exact path.
	{"fail-27-p1-release-yaml", unchanged, map[string]string{".github/workflows/release.yaml": "permissions:\n  packages: write\njobs: {}\n"},
		[]string{"release.yaml:1: workflow grants packages: write"}},
	{"fail-27-p1-capital-release", unchanged, map[string]string{".github/workflows/Release.yml": "permissions:\n  packages: write\njobs: {}\n"},
		[]string{"Release.yml:1: workflow grants packages: write"}},
	// P2: the exact job set and permissions.
	{"fail-27-p2-extra-job", appendText("\n  push2:\n    runs-on: ubuntu-24.04\n    permissions:\n      packages: write\n    steps:\n      - run: echo\n"),
		nil, []string{"job push2 is not in the release policy"}},
	{"fail-27-p2-missing-job", dropJob("attest-assets"), nil, []string{"job attest-assets of the release policy is missing"}},
	{"fail-27-p2-reusable-job", appendText("\n  x:\n    permissions:\n      packages: write\n    uses: ./.github/workflows/x.yml\n"),
		nil, []string{"job x is not in the release policy"}},
	{"fail-27-p2-job-uses", inJob("bundle", "    permissions:\n", "    uses: ./.github/workflows/x.yml\n    permissions:\n"),
		nil, []string{"job bundle: uses is not allowed: a job of release.yml calls no reusable workflow"}},
	{"fail-27-p2-build-packages-write", inJob("build", "      contents: read\n", "      contents: read\n      packages: write\n"),
		nil, []string{"job build: permissions must be exactly map[contents:read]"}},
	{"fail-27-p2-push-id-token", inJob("push", "      packages: write\n", "      packages: write\n      id-token: write\n"),
		nil, []string{"job push: permissions must be exactly map[contents:read packages:write]"}},
	{"fail-27-p2-top-level-permissions", inWorkflow("permissions: {}\n", "permissions:\n  contents: read\n"),
		nil, []string{"the top-level permissions must be exactly {}"}},
	// P3: pushes only through the checked bake step, by digest.
	{"fail-27-p3-output-name", inJob("push", pushOutputTrue, strings.TrimSuffix(pushOutputTrue, "\n")+",name=ghcr.io/keepia/mail-postfix\n"),
		nil, []string{"job push: BAKE_SET line \"${{ matrix.image }}.output=type=image,push-by-digest=true,name-canonical=true,push=true,name=", "job push: BAKE_SET lacks the line \"${{ matrix.image }}.output=type=image"}},
	{"fail-27-p3-bake-push-input", inJob("push", "          set: ${{ env.BAKE_SET }}\n", "          set: ${{ env.BAKE_SET }}\n          push: true\n"),
		nil, []string{"job push: step 8 must be exactly uses docker/bake-action"}},
	{"fail-27-p3-second-bake", inJob("push", pushedStep, "      - uses: docker/bake-action@59cb1203cd42bcefd40a1b6d73b589e48c86040e # v7.5.0\n        with:\n          source: .\n"+pushedStep),
		nil, []string{"job push has 11 steps", "job push: a second docker/bake-action step", "job push: docker/bake-action targets must be", "job push: the docker/bake-action step needs id: build", "job push: the step right before docker/bake-action must be exactly"}},
	{"fail-27-p3-third-output", inJob("push", attestLine, attestLine+"        ${{ matrix.image }}.output=type=registry,name=ghcr.io/keepia/mail-postfix:latest\n"),
		nil, []string{"job push: BAKE_SET line \"${{ matrix.image }}.output=type=registry"}},
	{"fail-27-p3-attest-sbom", inJob("push", attestLine, "${{ matrix.image }}.attest=type=sbom\n"),
		nil, []string{"BAKE_SET line \"${{ matrix.image }}.attest=type=sbom\" is not in the release policy", "BAKE_SET lacks the line \"${{ matrix.image }}.attest=type=provenance,mode=max\""}},
	{"fail-27-p3-attest-generator", inJob("push", attestLine, "${{ matrix.image }}.attest=type=provenance,mode=max,generator=docker.io/attacker/gen:latest\n"),
		nil, []string{"generator=docker.io/attacker/gen:latest\" is not in the release policy", "BAKE_SET lacks the line \"${{ matrix.image }}.attest=type=provenance,mode=max\""}},
	{"fail-27-p3-oci-dest-parent", inJob("push", ociOutput, "${{ matrix.image }}.output=type=oci,dest=../x.tar\n"),
		nil, []string{"dest=../x.tar\" is not in the release policy", "BAKE_SET lacks the line \"${{ matrix.image }}.output=type=oci,dest=pushed.tar\""}},
	{"fail-27-p3-oci-dest-subdir", inJob("push", ociOutput, "${{ matrix.image }}.output=type=oci,dest=out/pushed.tar\n"),
		nil, []string{"dest=out/pushed.tar\" is not in the release policy", "BAKE_SET lacks the line \"${{ matrix.image }}.output=type=oci,dest=pushed.tar\""}},
	{"fail-27-p3-runner-temp", inJob("push", ociOutput, "${{ matrix.image }}.output=type=oci,dest=${{ runner.temp }}/pushed.tar\n"),
		nil, []string{"dest=${{ runner.temp }}/pushed.tar\" is not in the release policy", "BAKE_SET lacks the line", "env BAKE_SET reads runner.temp"}},
	{"fail-27-p3-docker-push-after-verify", inJob("push", "      - uses: actions/upload-artifact", "      - run: docker push ghcr.io/keepia/mail-postfix:0.1.0\n      - uses: actions/upload-artifact"),
		nil, []string{"job push has 11 steps", "step 10 runs a text that is not one of this job's lines", "step 10 runs docker push: an image leaves a job with packages: write only through", "step 10 pushes ghcr.io/keepia/mail-postfix:0.1.0 by a name it did not tag", "step 10 tests, saves, pushes or tags the image; the step right before must be"}},
	{"fail-27-p3-imagetools-in-index", inJob("index", "      - id: index\n", "      - run: docker buildx imagetools create -t ghcr.io/keepia/mail:0.1.0 ghcr.io/keepia/mail@sha256:"+strings.Repeat("a", 64)+"\n      - id: index\n"),
		nil, []string{"job index has 7 steps", "step 6 runs a text that is not one of this job's lines", "step 6 runs buildx imagetools create: an image leaves"}},
	// P4: exact lines, nothing resolved.
	{"fail-27-p4-stdbuf", runStepBefore("push", "stdbuf -oL make publish"), nil, []string{"job push has 11 steps", "step 9 runs a text that is not one of this job's lines; nothing is resolved, the text must equal a line exactly (P4): \"stdbuf -oL make publish\""}},
	{"fail-27-p4-setsid", runStepBefore("push", "setsid make publish"), nil, []string{"job push has 11 steps", "(P4): \"setsid make publish\""}},
	{"fail-27-p4-find-exec", runStepBefore("push", `find . -maxdepth 0 -exec make publish \;`), nil, []string{"job push has 11 steps", "(P4): \"find . -maxdepth 0 -exec make publish \\\\;\""}},
	{"fail-27-p4-git-alias", runStepBefore("push", `git -c alias.p='!make publish' p`), nil, []string{"job push has 11 steps", "(P4): \"git -c alias.p='!make publish' p\""}},
	{"fail-27-p4-alias", runStepBefore("push", "shopt -s expand_aliases; alias p=make; p publish"), nil, []string{"job push has 11 steps", "(P4): \"shopt -s expand_aliases; alias p=make; p publish\""}},
	{"fail-27-p4-release-bundle-in-push", runStepBefore("push", "bash scripts/release-bundle.sh"), nil, []string{"job push has 11 steps", "(P4): \"bash scripts/release-bundle.sh\"", "it runs scripts/release-bundle.sh, which the check cannot resolve"}},
	{"fail-27-p4-mirror-in-push", runStepBefore("push", "sh scripts/ci-docker-mirror.sh"), nil, []string{"job push has 11 steps", "(P4): \"sh scripts/ci-docker-mirror.sh\""}},
	{"fail-27-p4-make-in-index", inJob("index", "      - id: index\n", "      - run: make images\n      - id: index\n"), nil, []string{"job index has 7 steps", "(P4): \"make images\""}},
	{"fail-27-p4-go-run-other", runStepBefore("push", "GOENV=off GOFLAGS=-mod=readonly GOWORK=off go run ./tools/other"), nil, []string{"job push has 11 steps", "go run ./tools/other\""}},
	{"fail-27-p4-check-line-suffix", inJob("push", `-build-set "$BAKE_SET"`+"\n", `-build-set "$BAKE_SET"; make publish`+"\n"),
		nil, []string{"step 7 runs a text that is not one of this job's lines", "the step right before docker/bake-action must be exactly",
			"job push: the step `run: " + lineEpoch + "` is required before the check step", "job push: step 7: it runs make, but the check finds no Makefile"}},
	{"fail-27-p4-verify-pushed-env", inJob("push", "          BAKE_METADATA: ${{ steps.build.outputs.metadata }}\n", "          BAKE_METADATA: ${{ steps.build.outputs.metadata }}\n          GOFLAGS: -toolexec=x\n"),
		nil, []string{"job push: step 9 must be exactly run: " + lineVerifyPushed}},
	// P5: no shell function, eval, -c, source or xargs (by construction,
	// with their own messages).
	{"fail-27-p5-forwarding-function", runStepBefore("push", `retry() { "$@"; }; retry make publish`), nil, []string{"job push has 11 steps", "step 9 runs a text that is not one of this job's lines", "step 9 defines a shell function: a job with packages: write defines no shell function (P5)"}},
	{"fail-27-p5-eval", runStepBefore("push", `eval "$X"`), nil, []string{"job push has 11 steps", "step 9 runs a text that is not one of this job's lines", "step 9 runs eval: a job with packages: write runs no eval, sh -c, source or xargs (P5)", "step 9: it runs $X, which the check cannot resolve"}},
	{"fail-27-p5-xargs", runStepBefore("push", "xargs make publish"), nil, []string{"job push has 11 steps", "step 9 runs a text that is not one of this job's lines", "step 9 runs xargs: a job with packages: write runs no eval"}},
	{"fail-27-p5-sh-c", inJob("index", "      - id: index\n", "      - run: sh -c make\n      - id: index\n"), nil, []string{"job index has 7 steps", "step 6 runs a text that is not one of this job's lines", "step 6 runs sh -c: a job with packages: write runs no eval, sh -c, source or xargs (P5)"}},
	// P6: needs and if exactly.
	{"fail-27-p6-release-needs", inJob("release", "    needs: [version, bundle, attest, attest-assets]\n", "    needs: [version, bundle, attest-assets]\n"), nil, []string{"job release: needs must be exactly [version bundle attest attest-assets]"}},
	{"fail-27-p6-push-if", inJob("push", "    if: ${{ !inputs.dry_run }}\n", ""), nil, []string{"job push: if must be exactly ${{ !inputs.dry_run }}"}},
	{"fail-27-p6-bundle-if", inJob("bundle", "(inputs.dry_run && needs.push-rehearsal.result == 'success') || ", ""), nil, []string{"job bundle: if must be exactly"}},
	// P7: no continue-on-error, container, services, env; no repository
	// code in release, attest and attest-assets.
	{"fail-27-p7-continue-on-error", inJob("push", pushedStep, pushedStep+"        continue-on-error: true\n"), nil, []string{"job push: step 9 has continue-on-error: a failed step must stop the release (P7)", "job push: step 9 has continue-on-error: a step of this job has no if"}},
	{"fail-27-p7-checkout-in-release", inJob("release", "    steps:\n", "    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"), nil,
		[]string{"job release: step 1 checks out the repository", "job release: step 1 uses actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, which is not one of this job's actions", "job release has 6 steps; the release policy has exactly 5"}},
	{"fail-27-p7-script-in-attest", inJob("attest-assets", "        run: sha256sum -c SHA256SUMS\n", "        run: sh scripts/release-sources.sh\n"), nil,
		[]string{"job attest-assets: step 2 runs repository or dependency code (scripts/)", "job attest-assets: step 2 runs a text that is not one of this job's lines"}},
	{"fail-27-p7-workflow-env", inWorkflow("permissions: {}\n", "permissions: {}\nenv:\n  X: y\n"), nil, []string{"release.yml has no workflow env",
		"job build: workflow env X is not allowed", "job push-rehearsal: workflow env X is not allowed", "job push: workflow env X is not allowed"}},
	// P8: trigger, inputs, run texts, VERSION.
	{"fail-27-p8-on-push", inWorkflow("on:\n  workflow_dispatch:\n", "on:\n  push:\n  workflow_dispatch:\n"), nil, []string{"on: must be exactly workflow_dispatch"}},
	{"fail-27-p8-workflow-call", inWorkflow("on:\n  workflow_dispatch:\n", "on:\n  workflow_call:\n  workflow_dispatch:\n"), nil, []string{"on: must be exactly workflow_dispatch"}},
	{"fail-27-p8-dry-run-default", inWorkflow("        type: boolean\n        default: true\n", "        type: boolean\n        default: false\n"), nil, []string{"input dry_run must be type boolean with default true"}},
	{"fail-27-p8-input-in-run", inJob("version", `sh scripts/version-policy.sh "$last" "$INPUT" <"$prs"`, `sh scripts/version-policy.sh "$last" "${{ inputs.version }}" <"$prs"`), nil, []string{"job version: step 4 has ${{ }} in its run text"}},
	{"fail-27-p8-version-from-event", inJob("build", "      VERSION: ${{ needs.version.outputs.version }}\n", "      VERSION: ${{ github.event.inputs.version }}\n"), nil, []string{"job build: env VERSION must be exactly", "job build: job env VERSION must be exactly"}},
	{"fail-27-p8-step-version", inJob("bundle", "          VERSION: ${{ needs.version.outputs.version }}\n", "          VERSION: ${{ inputs.version }}\n"), nil, []string{"release.yml: job bundle step 6 env VERSION must be exactly"}},
	// P9: exact actions; push and push-rehearsal step for step.
	{"fail-27-p9-other-action-in-index", inJob("index", "      - id: index\n", "      - uses: other/push@"+sha40+"\n      - id: index\n"), nil, []string{"job index has 7 steps", "step 6 uses other/push@" + sha40 + ", which is not one of this job's actions"}},
	{"fail-27-p9-login-action", inJob("push", pushedStep, "      - uses: docker/login-action@"+sha40+"\n"+pushedStep), nil, []string{"job push has 11 steps", "uses docker/login-action@" + sha40 + ", which is not one of this job's actions"}},
	{"fail-27-p9-github-script", inJob("push", pushedStep, "      - uses: actions/github-script@"+sha40+"\n"+pushedStep), nil, []string{"job push has 11 steps", "uses actions/github-script@" + sha40 + ", which is not one of this job's actions"}},
	{"fail-27-p9-twin-extra-step", runStepBefore("push-rehearsal", "echo rehearsal only"), nil, []string{"job push-rehearsal has 10 steps; the release policy has exactly 9", "(P4): \"echo rehearsal only\""}},
	{"fail-27-p9-twin-push-true", inJob("push-rehearsal", pushOutputFalse, pushOutputTrue), nil, []string{"job push-rehearsal: BAKE_SET line \"${{ matrix.image }}.output=type=image,push-by-digest=true,name-canonical=true,push=true\" is not in the release policy", "job push-rehearsal: BAKE_SET lacks the line"}},
	{"fail-27-p9-unpinned-action", inJob("push", "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2", "actions/upload-artifact@v7"), nil, []string{"step 10 uses actions/upload-artifact@v7, which is not one of this job's actions (P9"}},
	{"fail-27-p9-upload-pushed-tar", inJob("push", "          path: ${{ runner.temp }}/digest/\n", "          path: pushed.tar\n"), nil, []string{"job push: step 10 must be exactly uses actions/upload-artifact"}},
	// B1 M3: SOURCE_DATE_EPOCH is required.
	{"fail-27-epoch-missing", inJob("push", "        run: echo \"SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)\" >>\"$GITHUB_ENV\"\n", "        run: echo no epoch\n"),
		nil, []string{"job push: the step `run: " + lineEpoch + "` is required", "step 5 runs a text that is not one of this job's lines"}},
	{"fail-27-epoch-missing-build", inJob("build", "        run: echo \"SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)\" >>\"$GITHUB_ENV\"\n", "        run: echo no epoch\n"),
		nil, []string{"job build: the step `run: " + lineEpoch + "` is required"}},
	// Revision 4: latest moves only in a real release, after the release.
	{"fail-27-latest-dry", inJob("latest", "    if: ${{ !inputs.dry_run }}\n", ""), nil, []string{"job latest: if must be exactly ${{ !inputs.dry_run }}"}},
	{"fail-27-latest-elsewhere", inJob("index", "      - id: index\n", "      - env:\n          VERSION: ${{ needs.version.outputs.version }}\n          INDEX_DIGESTS: x\n        run: "+lineMoveLatest+"\n      - id: index\n"),
		nil, []string{"job index has 7 steps", "step 6 runs a text that is not one of this job's lines"}},
	{"fail-27-latest-in-rehearsal", runStepBefore("push-rehearsal", lineMoveLatest), nil, []string{"job push-rehearsal has 10 steps", "-move-latest\""}},
	{"fail-27-other-tag", inJob("latest", "      - env:\n", "      - run: docker buildx imagetools create -t ghcr.io/keepia/mail:0.1 ghcr.io/keepia/mail:0.1.0\n      - env:\n"),
		nil, []string{"job latest has 6 steps", "step 5 runs a text that is not one of this job's lines", "step 5 runs buildx imagetools create"}},
	{"fail-27-latest-needs", inJob("latest", "    needs: [version, index, release]\n", "    needs: [version, index]\n"), nil, []string{"job latest: needs must be exactly [version index release]"}},
	// Round 2 of #71. Review B, B1: setup-go's cache stays off.
	{"fail-27-setup-go-cache", inJob("push", "          cache: false\n", ""), nil, []string{"job push: step 2 must be exactly uses actions/setup-go@" + actionPins["actions/setup-go"]}},
	{"fail-27-setup-go-cache-build", inJob("build", "          cache: false\n", ""), nil, []string{"job build: step 2 uses actions/setup-go without cache: false"}},
	// Review A, B1: an env given as one expression.
	{"fail-27-p4-env-expression", inJob("push", "      - name: Commit time\n", "      - name: Commit time\n        env: ${{ fromJSON('{\"BASH_ENV\":\"scripts/image-test.sh\"}') }}\n"),
		nil, []string{"job push: step 5: env is not a mapping", "job push: step 5 must be exactly run: " + lineEpoch}},
	{"fail-27-p7-env-expression", inJob("release", "        working-directory: dist\n        run: sha256sum -c SHA256SUMS\n", "        working-directory: dist\n        env: ${{ fromJSON('{\"BASH_ENV\":\"x\"}') }}\n        run: sha256sum -c SHA256SUMS\n"),
		nil, []string{"job release: step 2: env is not a mapping", "job release: step 2 must be exactly run: sha256sum -c SHA256SUMS"}},
	{"fail-27-bake-env-expression", inJob("build", "    env:\n      BAKE_TARGET: ${{ matrix.image }}\n      PLATFORM: linux/${{ matrix.arch }}\n      VERSION: ${{ needs.version.outputs.version }}\n", "    env: ${{ fromJSON('{}') }}\n    x-env:\n      BAKE_TARGET: ${{ matrix.image }}\n      PLATFORM: linux/${{ matrix.arch }}\n      VERSION: ${{ needs.version.outputs.version }}\n"),
		nil, []string{"job build: the job env is not a mapping (${{ fromJSON('{}') }})", "job build: the job env is not a mapping\n", "job build: key x-env is not in the release policy"}},
	// Review A, B2: the syft rule matches a command that runs syft.
	{"fail-27-syft-version", inJob("build", "syft@v1.57.1 scan", "syft@latest scan"), nil, []string{"job build: step 14 runs syft other than as"}},
	{"fail-27-syft-binary", inJob("build", "        run: go run github.com/anchore/syft/cmd/syft@v1.57.1 scan", "        run: syft scan"), nil, []string{"job build: step 14 runs syft other than as"}},
	// Review A, B3: the release modes and the login only in the exact jobs.
	{"fail-27-latest-in-bundle", inJob("bundle", "      - uses: actions/upload-artifact", "      - env:\n          VERSION: ${{ needs.version.outputs.version }}\n          INDEX_DIGESTS: ${{ needs.index.outputs.digests }}\n        run: "+lineMoveLatest+"\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 runs -move-latest: the release modes run only in push, push-rehearsal, index and latest"}},
	{"fail-27-verify-pushed-in-build", inJob("build", "      - name: SBOM\n", "      - run: "+lineVerifyPushed+"\n      - name: SBOM\n"), nil, []string{"job build: step 14 runs -verify-pushed: the release modes run only in"}},
	{"fail-27-login-in-bundle", inJob("bundle", "      - uses: actions/upload-artifact", "      - env:\n          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n        run: "+lineLogin+"\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 runs docker login: only push, index and latest log in to GHCR"}},
	// Review B, N1: the policy's pin, not any commit of the action.
	{"fail-27-p9-other-pin", inJob("push", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@"+sha40), nil, []string{"job push: step 1 uses actions/checkout at " + sha40 + ", not at the policy's pin"}},
	// Revision 5 (B6): the concurrency that serialises the moves.
	{"fail-27-concurrency-missing", inWorkflow("concurrency:\n  group: release\n  cancel-in-progress: false\n", ""), nil, []string{"the workflow-level concurrency must be exactly {group: release, cancel-in-progress: false}"}},
	{"fail-27-concurrency-cancel", inWorkflow("  cancel-in-progress: false\n", "  cancel-in-progress: true\n"), nil, []string{"the workflow-level concurrency must be exactly"}},
	{"fail-27-concurrency-group", inWorkflow("  group: release\n", "  group: release-${{ github.run_id }}\n"), nil, []string{"the workflow-level concurrency must be exactly"}},
	{"fail-27-concurrency-job", inJob("latest", "    permissions:\n", "    concurrency: latest\n    permissions:\n"), nil, []string{"job latest: concurrency is not allowed: only the workflow-level concurrency group release serialises the runs (B6)"}},
	// #27 part 4b, #71 review B N2: attest, attest-assets and release have
	// exact steps.
	{"fail-27-4b-release-curl-sh", inJob("release", "SOURCES.md SHA256SUMS\n", "SOURCES.md SHA256SUMS\n          curl -sSf https://example.org/install | sh\n"),
		nil, []string{"job release: step 4 runs a text that is not one of this job's lines"}},
	{"fail-27-4b-attest-third-party", inJob("attest", "      - name: Checksum\n", "      - uses: other/sign@"+sha40+"\n      - name: Checksum\n"),
		nil, []string{"job attest: step 3 uses other/sign@" + sha40 + ", which is not one of this job's actions", "job attest has 20 steps; the release policy has exactly 19"}},
	{"fail-27-4b-attest-assets-github-env", inJob("attest-assets", "      - uses: actions/attest@", "      - run: echo \"BASH_ENV=$PWD/x\" >>\"$GITHUB_ENV\"\n      - uses: actions/attest@"),
		nil, []string{"job attest-assets: step 3 runs a text that is not one of this job's lines", "job attest-assets has 4 steps; the release policy has exactly 3"}},
	{"fail-27-4b-release-km", inJob("release", "      - name: Create the tag\n", "      - run: ./keepia-mail/km migrate\n      - name: Create the tag\n"),
		nil, []string{"job release: step 3 runs a repository-relative command", "job release: step 3 runs a text that is not one of this job's lines", "job release has 6 steps"}},
	{"fail-27-4b-sbom-subject", inJob("attest", "subject-digest: ${{ steps.subjects.outputs.postfix-amd64 }}", "subject-digest: ${{ steps.subjects.outputs.postfix }}"),
		nil, []string{"job attest: step 9 must be exactly uses actions/attest@" + actionPins["actions/attest"]}},
	{"fail-27-4b-notes-start-tag", inJob("release", `--generate-notes "${start[@]}"`, `--generate-notes --notes-start-tag "$BASE"`),
		nil, []string{"job release: step 4 runs a text that is not one of this job's lines"}},
	{"fail-27-4b-cleanup-if", inJob("release", "        if: (failure() || cancelled()) && steps.tag.outcome == 'success'\n", "        if: failure()\n"),
		nil, []string{`, if "(failure() || cancelled()) && steps.tag.outcome == 'success'"): if "failure()", want "(failure() || cancelled()) && steps.tag.outcome == 'success'"`}},
	{"fail-27-4b-attest-push-to-registry", inJob("attest-assets", "          subject-path: dist/*\n", "          subject-path: dist/*\n          push-to-registry: true\n"),
		nil, []string{"job attest-assets: step 3 must be exactly uses actions/attest@"}},
	// #71 delta reviews A N1, B D2: a release mode in any spelling.
	{"fail-27-4b-mode-equals", inJob("bundle", "      - uses: actions/upload-artifact", "      - run: GOENV=off GOFLAGS=-mod=readonly GOWORK=off go run ./tools/check-image-pins -move-latest=true\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 runs -move-latest: the release modes run only in"}},
	{"fail-27-4b-mode-bash-c", inJob("version", "      - name: Images\n", "      - run: bash -c 'go run ./tools/check-image-pins -publish-index=1'\n      - name: Images\n"),
		nil, []string{"job version: step 6 runs -publish-index: the release modes run only in"}},
	{"fail-27-4b-mode-quoted", inJob("build", "      - name: SBOM\n", "      - run: go run ./tools/check-image-pins \"-verify-\"pushed\n      - name: SBOM\n"),
		nil, []string{"job build: step 14 runs -verify-pushed: the release modes run only in"}},
	{"fail-27-4b-login-bash-c", inJob("bundle", "      - uses: actions/upload-artifact", "      - run: bash -c 'echo \"$T\" | docker login ghcr.io -u x --password-stdin'\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 runs docker login: only push, index and latest log in to GHCR"}},
	// #71 delta review A N2: no other syft, no other container.
	{"fail-27-4b-docker-run-syft", inJob("build", "      - name: SBOM\n", "      - run: docker run --rm anchore/syft:latest scan \"docker-archive:$RUNNER_TEMP/image.tar\"\n      - name: SBOM\n"),
		nil, []string{"job build: step 14 runs a container (docker run): in release.yml only the build row's package-list line does"}},
	{"fail-27-4b-docker-run-unpinned", inJob("version", "      - name: Images\n", "      - run: docker run --rm alpine:latest true\n      - name: Images\n"),
		nil, []string{"job version: step 6 runs a container (docker run)"}},
	{"fail-27-4b-podman-container-run", inJob("bundle", "      - uses: actions/upload-artifact", "      - run: podman container run --rm docker.io/library/busybox true\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 runs a container (podman run)"}},
	{"fail-27-4b-sbom-action", inJob("build", "      - name: SBOM\n", "      - uses: anchore/sbom-action@"+sha40+"\n      - name: SBOM\n"),
		nil, []string{"job build: step 14 uses anchore/sbom-action@" + sha40 + ": syft runs only as"}},
	{"fail-27-4b-docker-uses", inJob("bundle", "      - uses: actions/upload-artifact", "      - uses: docker://anchore/syft:latest\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 uses docker://anchore/syft:latest: a step of release.yml runs no image"}},
	// #71 delta reviews A N3, B D1: action names without case; no cache.
	{"fail-27-4b-setup-go-case", inJob("build", "uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version-file: go.mod\n          cache: false\n",
		"uses: Actions/Setup-Go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version-file: go.mod\n"),
		nil, []string{"job build: step 2 uses actions/setup-go without cache: false"}},
	{"fail-27-4b-actions-cache", inJob("build", "      - name: Commit time\n", "      - uses: actions/cache@"+sha40+"\n        with:\n          path: ~/go/pkg/mod\n          key: go\n      - name: Commit time\n"),
		nil, []string{"job build: step 5 uses actions/cache@" + sha40 + ": release.yml restores and saves no cache"}},
	{"fail-27-4b-actions-cache-restore-case", inJob("bundle", "      - uses: actions/upload-artifact", "      - uses: Actions/Cache/restore@"+sha40+"\n        with:\n          path: ~/go/pkg/mod\n          key: go\n      - uses: actions/upload-artifact"),
		nil, []string{"job bundle: step 10 uses Actions/Cache/restore@" + sha40 + ": release.yml restores and saves no cache"}},
	// #71 delta review B, D3: a string "false" reads apart from false.
	{"fail-27-4b-setup-go-cache-string", inJob("index", "          cache: false\n", "          cache: \"false\"\n"),
		nil, []string{`job index: step 2 must be exactly uses actions/setup-go@` + actionPins["actions/setup-go"] + ` with map[string]interface {}{"cache":false, "go-version-file":"go.mod"}: with map[string]interface {}{"cache":"false", "go-version-file":"go.mod"}`}},
	// #71 review B, N6: the BuildKit image is pinned, in release.yml and
	// in every other workflow.
	{"fail-27-4b-buildx-floating", inJob("build", "          driver-opts: image="+buildkitImage+"\n", ""),
		nil, []string{"job build: step 4 uses docker/setup-buildx-action with", "job build: step 4: docker/setup-buildx-action starts BuildKit from the floating moby/buildkit:buildx-stable-1"}},
	{"fail-27-4b-buildx-unpinned", inJob("push", "          driver-opts: image="+buildkitImage+"\n", "          driver-opts: image=moby/buildkit:latest\n"),
		nil, []string{"job push: step 3 must be exactly uses docker/setup-buildx-action@", `job push: step 3: BuildKit image (driver-opts) "moby/buildkit:latest" is not pinned`}},
	{"fail-27-4b-ci-buildx-floating", unchanged, map[string]string{".github/workflows/other.yml": "permissions:\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1\n"},
		[]string{"other.yml:4: job x: step 1: docker/setup-buildx-action starts BuildKit from the floating moby/buildkit:buildx-stable-1"}},
}

// copyTree copies the fixture tree to dir.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o750)
		}
		b, err := os.ReadFile(p) //nolint:gosec // the test's own fixture
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReleaseSurface is test 18: each fail-27-* case is red for its
// stated findings, and only those. CHECK_IMAGE_PINS_DUMP=<dir> writes each
// case's tree there, for the counter-proof against the base commit.
func TestReleaseSurface(t *testing.T) {
	base := releaseFixture(t)
	dump := os.Getenv("CHECK_IMAGE_PINS_DUMP")
	seen := map[string]bool{}
	for _, c := range releaseCases {
		t.Run(c.name, func(t *testing.T) {
			if seen[c.name] {
				t.Fatalf("duplicate case name")
			}
			seen[c.name] = true
			root := t.TempDir()
			if dump != "" {
				root = filepath.Join(dump, c.name)
			}
			copyTree(t, releaseFixtureDir, root)
			wf := c.mutate(t, base)
			if wf == base && len(c.extra) == 0 {
				t.Fatal("the case changes nothing")
			}
			write(t, root, ".github/workflows/release.yml", wf)
			for p, s := range c.extra {
				write(t, root, p, s)
			}
			var out, errOut bytes.Buffer
			code := run([]string{root}, &out, &errOut)
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s%s", code, out.String(), errOut.String())
			}
			for _, w := range c.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q", w)
				}
			}
			if n := strings.Count(out.String(), "\n") - 1; n != len(c.want) {
				t.Errorf("%d findings, want %d", n, len(c.want))
			}
			if t.Failed() {
				t.Logf("output:\n%s%s", out.String(), errOut.String())
			}
		})
	}
}

// TestPushJobScript: a script on the push jobs' allowlist (empty in the
// repository; the test brings its own) may hold no forwarding function,
// eval, sh -c, source or xargs (P5).
func TestPushJobScript(t *testing.T) {
	cases := []struct {
		src  string
		want []string
	}{
		{"#!/bin/sh\nf() { \"$1\"; }\nf make publish\n", []string{"function f runs its arguments as a command"}},
		{"#!/bin/sh\nretry() { for i in 1 2; do \"$@\" && return; done; }\nretry docker push x\n", []string{"function retry runs its arguments as a command"}},
		{"#!/bin/sh\neval \"$X\"\n", []string{"runs eval:"}},
		{"#!/bin/sh\n. ./lib.sh\n", []string{"runs .:"}},
		{"#!/bin/sh\nxargs make < list\n", []string{"runs xargs:"}},
		{"#!/bin/sh\nbash -c \"$CMD\"\n", []string{"runs bash -c:"}},
		{"#!/bin/sh\nlog() { echo \"$1\"; }\nlog hello\n", nil},
	}
	for _, c := range cases {
		got := checkPushJobScript([]byte(c.src))
		if len(got) != len(c.want) {
			t.Errorf("%q: findings %q, want %d", c.src, got, len(c.want))
			continue
		}
		for i, w := range c.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%q: finding %q lacks %q", c.src, got[i], w)
			}
		}
	}
	// In repository mode, an allowlisted script is read and checked.
	root := t.TempDir()
	copyTree(t, releaseFixtureDir, root)
	write(t, root, "scripts/push.sh", "#!/bin/sh\nf() { \"$1\"; }\nf make publish\n")
	pushJobScripts["scripts/push.sh"] = true
	defer delete(pushJobScripts, "scripts/push.sh")
	var out, errOut bytes.Buffer
	if code := run([]string{root}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "push.sh:0: function f runs its arguments") {
		t.Fatalf("exit %d, want 1 with the function named:\n%s%s", code, out.String(), errOut.String())
	}
}

// TestReleaseBuildMode is test 19: build mode in release.yml resolves the
// exact output, attest and cache lines, the tags and VERSION.
func TestReleaseBuildMode(t *testing.T) {
	if !haveBuildx(t) {
		t.Skip("docker buildx is not available")
	}
	repo := filepath.Join("testdata", "repos", "pass-27-bake")
	t.Setenv("PLATFORM", "linux/amd64")
	const (
		from   = "postfix.cache-from=type=gha,scope=release-postfix-amd64"
		img    = "postfix.output=type=image,push-by-digest=true,name-canonical=true,push=true"
		oci    = "postfix.output=type=oci,dest=pushed.tar"
		attest = "postfix.attest=type=provenance,mode=max"
		to     = "postfix.cache-to=type=gha,mode=max,scope=release-postfix-amd64"
	)
	push := strings.Join([]string{from, img, oci, attest}, "\n")
	cases := []struct {
		name, target, sets, version string
		registry                    *string
		code                        int
		want                        string
	}{
		{"build row", "postfix", to, "0.1.0", nil, 0, "build postfix resolves to pinned images"},
		{"push row", "postfix", push, "0.1.0", nil, 0, "build postfix resolves to pinned images"},
		{"rehearsal row", "postfix", strings.Replace(push, "push=true", "push=false", 1), "0.1.0", nil, 0, "build postfix resolves"},
		{"attest sbom", "postfix", strings.Replace(push, attest, "postfix.attest=type=sbom", 1), "0.1.0", nil, 1, "a release build's attest must be exactly"},
		{"attest generator", "postfix", strings.Replace(push, attest, attest+",generator=docker.io/attacker/gen:latest", 1), "0.1.0", nil, 1, "a release build's attest must be exactly"},
		{"foreign scope", "postfix", strings.Replace(push, "release-postfix-amd64", "release-olefy-amd64", 1), "0.1.0", nil, 1, "a release build's cache-from must be exactly"},
		{"CI scope in a release build", "postfix", strings.Replace(push, from, "postfix.cache-from=type=gha,scope=postfix-amd64", 1), "0.1.0", nil, 1, `target "postfix": output is not allowed`},
		{"VERSION=dev", "postfix", push, "dev", nil, 1, `a release build needs VERSION as X.Y.Z`},
		{"REGISTRY set", "postfix", push, "0.1.0", ptr("ghcr.io/other"), 1, "a release build takes the default REGISTRY"},
		{"output to a registry", "postfix", push + "\npostfix.output=type=registry", "0.1.0", nil, 1, "a release build's output must be exactly"},
		{"OCI dest elsewhere", "postfix", strings.Replace(push, "dest=pushed.tar", "dest=out/pushed.tar", 1), "0.1.0", nil, 1, "a release build's output must be exactly"},
		{"push and cache-to", "postfix", push + "\n" + to, "0.1.0", nil, 1, "a release build's cache-to must be exactly"},
		{"build with cache-from", "postfix", to + "\n" + strings.Replace(from, "cache-from", "cache-from", 1), "0.1.0", nil, 1, "a release build's cache-from must be exactly"},
		// A target tag of another repository (the tags replace the
		// output's name with push-by-digest; buildx build/opt.go).
		{"foreign tag", "other", strings.ReplaceAll(push, "postfix", "other"), "0.1.0", nil, 1, "a release build's tags must be exactly [ghcr.io/keepia/mail-other:0.1.0]"},
		// Outside a release build, output and attest stay forbidden.
		{"output in CI", "postfix", "postfix.cache-from=type=gha,scope=postfix-amd64\n" + oci, "", nil, 1, `target "postfix": output is not allowed`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("VERSION", c.version)
			if c.version == "" {
				os.Unsetenv("VERSION") //nolint:errcheck // t.Setenv restores it
			}
			if c.registry != nil {
				t.Setenv("REGISTRY", *c.registry)
			} else {
				t.Setenv("REGISTRY", "")
				os.Unsetenv("REGISTRY") //nolint:errcheck // t.Setenv restores it
			}
			var out, errOut bytes.Buffer
			code := run([]string{"-build", c.target, "-build-set", c.sets, repo}, &out, &errOut)
			if code != c.code || !strings.Contains(out.String(), c.want) {
				t.Fatalf("exit %d, want %d with %q:\n%s%s", code, c.code, c.want, out.String(), errOut.String())
			}
		})
	}
}

func ptr(s string) *string { return &s }

// TestBuildRefusesPushedTar: -build fails if pushed.tar exists in any form
// before the bake step (revision 3, B5): a file, a directory, or a
// symlink, also a committed one that would redirect the OCI output.
func TestBuildRefusesPushedTar(t *testing.T) {
	for _, kind := range []string{"file", "dir", "symlink", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, pushedTar)
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(p, nil, 0o600)
			case "dir":
				err = os.Mkdir(p, 0o750)
			case "symlink":
				err = os.Symlink(filepath.Join(root, "elsewhere"), p)
				if err == nil {
					err = os.WriteFile(filepath.Join(root, "elsewhere"), nil, 0o600)
				}
			case "dangling symlink":
				err = os.Symlink("/nonexistent/keepia", p)
			}
			if err != nil {
				t.Fatal(err)
			}
			if msg := pushedTarProblem(root); !strings.Contains(msg, "exists before the build") {
				t.Fatalf("got %q, want a refusal", msg)
			}
		})
	}
	if msg := pushedTarProblem(t.TempDir()); msg != "" {
		t.Fatalf("an empty tree: %q", msg)
	}
}
