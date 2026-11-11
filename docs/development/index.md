# Development

This page grows with the code. For now it describes the checks that run on
every pull request; setup, tests and migrations follow with the first Go
code (#6).

## Security checks

The required checks are `secret-scan`, `links` and `workflows`. Each runs on
every pull request and every push to `main`; no workflow with a required job
has a `paths` filter.

```sh
make secrets-test secrets     # secret scan: self-test, then the full history
make links-test links         # Markdown links: self-test, then the repository
make workflows-test workflows # action pins: self-test; then actionlint, pins, labels.json
```

The tools are pinned in the [Makefile](../../Makefile) and built with the
project's toolchain into `bin/`, verified through the Go checksum database.

### Workflows and action pinning

The `workflows` check (`.github/workflows/ci.yml`) runs:

- [actionlint](https://github.com/rhysd/actionlint) (`ACTIONLINT_VERSION`)
  on all workflows, without shellcheck and pyflakes so the result does not
  depend on what is installed. It reports, among other things, untrusted
  input such as `${{ github.event.pull_request.title }}` used directly in a
  `run:` script;
- [`scripts/check-action-pins.sh`](../../scripts/check-action-pins.sh): every
  `uses:` is pinned to a full 40-character commit SHA with a `# vX.Y.Z`
  comment (`owner/repo@<sha> # v1.2.3`); local actions (`./…`) are allowed,
  a `docker://` image needs an `@sha256:` digest. Its self-test is
  `scripts/check-action-pins-test.sh` with the fixtures in
  `scripts/testdata/check-action-pins/`;
- `jq empty .github/labels.json`: the label file is valid JSON.

Workflows run with read-only permissions (`contents: read`) and
`persist-credentials: false` unless a job needs more. A new action is a new
external service and needs the maintainer's OK.

### Dependencies

- Dependabot opens weekly update pull requests for Go modules and GitHub
  Actions (`.github/dependabot.yml`). It waits 14 days after a release
  before it opens a version update (`cooldown`); security updates are
  exempt.
- Dependabot does not update tools that the Makefile installs with
  `go install pkg@version` (gitleaks, actionlint): bump them by hand in the
  Makefile.

### Secret scanning

The `secret-scan` check (`.github/workflows/secrets.yml`) runs
[gitleaks](https://github.com/gitleaks/gitleaks) with its built-in rules and
the narrow allowlist in [`.gitleaks.toml`](../../.gitleaks.toml):

- on every pull request: the commits the pull request adds
  (`base..head`);
- on every push to `main`: the commits the push adds (`before..after`). A
  push without a previous commit, or whose previous commit is not in the
  clone, scans only its last commit and says so in the log.

The workflow has no `paths` filter, so the check runs on every pull request;
`secret-scan` is a required check. Secret values are redacted in the log. Pull
request runs cancel older runs of the same pull request; push runs are never
cancelled.

```sh
make secrets        # scan the full history of all local refs
make secrets-test   # self-test: the scan fails and passes where it should
```

gitleaks is pinned in the Makefile (`GITLEAKS_VERSION`) and verified through
the Go checksum database. Dependabot does not update it: bump it by hand,
then rescan the full history with `make secrets` on a clone with all
branches and tags.

**If the check finds a credential:**

1. Treat it as leaked: rotate or revoke it first. Removing the commit does
   not help, because the value stays in the history and in clones.
2. Never post the value on GitHub (issues, pull requests, comments). Report
   it to the maintainer privately.
3. Remove it from the branch. On a pull request branch, rewrite the branch
   so no commit contains the value. On `main` the history is not rewritten:
   after rotating, add the finding's fingerprint (`commit:file:rule:line`,
   printed by gitleaks) to `.gitleaksignore` with a comment.

**False positives** (a fake key in a test fixture) get a narrow entry in
`.gitleaks.toml`: one `[[allowlists]]` block with `condition = "AND"`, the
fixture's exact path and a regex for the fake value, and a comment saying why
it is safe. Global regexes and path globs are not allowed. Better still,
build fake credentials at runtime in tests, so nothing in the repository
matches a rule (see `scripts/secret-scan-test.sh`).

**Known fake finding.** The proof that the check fails a pull request with a
credential was a throwaway pull request, #TBD (commit `TBD`), closed
unmerged. Its only commit adds `proof/fake-token.txt` with the fake GitHub
token that `scripts/secret-scan-test.sh` builds at runtime (rule
`github-pat`); it is not a real credential. GitHub keeps that commit as
`refs/pull/TBD/head`, so a full-history rescan that includes `refs/pull/*`
(for example after a gitleaks bump) reports it. This finding is the known
fake: it gets no allowlist entry and no `.gitleaksignore` entry; rescans
leave out `refs/pull/*`.

### CodeQL

CodeQL runs as GitHub's default setup (a repository setting, no workflow
file): the default query suite on the languages GitHub detects, today the
workflows (`actions`), and Go once there is Go code. It is not a required
check. Alerts are never dismissed to make a check green; they are fixed.

### Links

The `links` check (`.github/workflows/ci.yml`) runs
[`scripts/check-links.sh`](../../scripts/check-links.sh): every relative
Markdown link in the repository's Markdown files must point to an existing
file or directory, resolved from the linking file's directory, and a
`#heading` anchor must match a heading of the target (GitHub's slug:
lowercase, punctuation dropped, spaces to hyphens). Links inside code spans
and fenced code blocks are ignored; external links are not fetched. Its
self-test is `scripts/check-links-test.sh` with the fixtures in
`scripts/testdata/check-links/`, which the check itself skips.
