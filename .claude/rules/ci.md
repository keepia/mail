---
paths:
  - ".github/workflows/**"
  - "scripts/ci-*"
  - "scripts/check-*"
  - "tools/check-action-pins/**"
  - "Makefile"
  - "go.mod"
---
# CI
- `secret-scan`, `links` and `workflows` are the required checks. A workflow with a required job has no `paths` filter, so the check runs on every pull request.
- Until the ruleset lists a new `ci.yml` job, it counts as required for merges.
- Every `uses:` is pinned to a full commit SHA with a `# vX.Y.Z` comment, in block style (`tools/check-action-pins`, a YAML parser; `make workflows`). A new action or registry is a new external service and needs the maintainer's OK.
- `permissions: contents: read` and `persist-credentials: false` on checkout, unless a job needs more.
- `release.yml` is held to rule 7 of `tools/check-image-pins` (`.claude/rules/docker.md`): a change to it, or a Dependabot bump of an action it uses, also changes `actionPins` in `tools/check-image-pins/release.go`. Every `docker/setup-buildx-action` names the pinned BuildKit image (`driver-opts: image=moby/buildkit:vX.Y.Z@sha256:…`), bumped by hand in `ci.yml`, `release.yml` and the tool's `buildkitImage` together. A real release needs the maintainer's OK, except `v0.1.0`, pre-approved after a green dry run (6845990778; `docs/development/process.md`, "Releases"). Every `docker/setup-buildx-action` has exactly CI's inputs, the pinned image in `driver-opts` and the mirror in `buildkitd-config-inline` (no `driver`, no other entry; #66 D3); `release.yml`'s `push-rehearsal` adds `network=host` to `driver-opts` (its local registry service, #75), no other job does. No step creates or selects another builder or context (`docker buildx create`/`use`, `docker builder create`/`use`, `docker context create`/`import`/`use`; in a job that builds, also in a script it runs), and no env sets `BUILDX_BUILDER`, `DOCKER_CONTEXT` or `DOCKER_HOST` (#66 D2). Its `registry` service image is bumped by hand in `release.yml` and the tool's `registryImage` together.
- A change to `.github/workflows/`, `tools/check-action-pins/`, the Makefile's `workflows`/`workflows-test` targets, or the `go.yaml.in/yaml/v3` line in `go.mod` gets `second-review`. A change to `secrets.yml` or `scripts/secret-scan-*` also needs the maintainer's OK (`docs/development/process.md`, "4. Pull request").
