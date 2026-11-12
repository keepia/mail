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
- A change to `.github/workflows/`, `tools/check-action-pins/`, the Makefile's `workflows`/`workflows-test` targets, or the `go.yaml.in/yaml/v3` line in `go.mod` gets `second-review`. A change to `secrets.yml` or `scripts/secret-scan-*` also needs the maintainer's OK (`docs/development/process.md`, "4. Pull request").
