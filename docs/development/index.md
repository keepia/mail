# Development

This page grows with the code. It describes the setup, the tests, the
database migrations, the `km` wrapper and the checks that run on every pull
request.

## Setup

- Go: the version in [`go.mod`](../../go.mod) (`toolchain`); with
  `GOTOOLCHAIN=auto` (the default) an older Go downloads it.
- PostgreSQL 18 with a role that may create databases (`CREATEDB`), for the
  database tests. For example:

  ```sh
  docker run -d --rm --name keepia-test-pg -p 127.0.0.1:5432:5432 \
    -e POSTGRES_USER=keepia -e POSTGRES_PASSWORD=keepia -e POSTGRES_DB=keepia \
    mirror.gcr.io/library/postgres:18
  ```

```sh
make build   # bin/keepia-mail
```

`keepia-mail` reads its configuration from the environment:

| Variable | Default | Used by |
|---|---|---|
| `KEEPIA_DATABASE_URL` | none (required) | `serve`, `migrate`; holds the password and is never logged. Percent-encode `@`, `/`, `?` and `#` in the user or password (`%40`, `%2F`, `%3F`, `%23`); a URL with a stray `@` is rejected without showing any part of it |
| `KEEPIA_LISTEN` | `127.0.0.1:8080` | `serve` and `healthcheck`; flag `--listen` |
| `KEEPIA_LOG_LEVEL` | `info` | `serve` (`debug`, `info`, `warn`, `error`) |

Commands: `serve` (migrate, then answer `GET /healthz`), `migrate`,
`migrate status`, `healthcheck` and `--version`.

## Tests

This is the test command the implementer and reviewer agents run:

```sh
make test       # all tests, -race -shuffle=on -count=1, with TEST_DATABASE_URL
make test-unit  # the tests that need no database; the database tests skip
make lint       # golangci-lint (.golangci.yml), version pinned in the Makefile
make vuln       # govulncheck, version pinned in the Makefile
```

`make test` uses `TEST_DATABASE_URL` (default
`postgres://keepia:keepia@localhost:5432/keepia?sslmode=disable`). Every
database test creates a database of its own, `keepia_test_<hex>`, and drops
it when it ends (`internal/store/storetest`). Without `TEST_DATABASE_URL`
the database tests skip, except in CI (`CI` set): there they fail, so CI
never passes with them skipped. Test rules: `.claude/rules/go-tests.md`.

CI runs the jobs `test` (against a `postgres:18` service), `lint` and
`vulncheck` on every pull request and every push to `main`.

## Database migrations

Migrations are SQL files for [goose](https://github.com/pressly/goose) in
`internal/store/migrations/`, embedded in the binary. `00001_baseline.sql`
is a no-op; the first tables come with the data model (#2).

- `keepia-mail migrate` applies the pending migrations; `keepia-mail migrate
  status` lists them.
- `keepia-mail serve` applies them first and opens its listener only
  afterwards, so a healthy `/healthz` also means the schema is current.
- Two instances starting at once apply each version once: goose takes the
  PostgreSQL advisory lock `4097083626` (goose's default lock id). It polls
  every 5 s for up to 5 minutes; after that `serve` and `migrate` exit 1
  with an error naming the lock, and `serve` never listens.
- Never edit a migration that is on `main`; add a new one. `Down` must work
  and is tested. Rules: `.claude/rules/migrations.md`.

## Wrapper

`km` runs `keepia-mail` commands through Docker Compose, for example
`./km migrate`. It starts the Compose service `postgres` (`docker compose up
-d --wait postgres`), then runs the command in a one-off container of the
service `keepia`, whose entrypoint is `keepia-mail` (`docker compose run
--rm -T keepia …`), with `--build` when a `Dockerfile` lies next to it. Its
exit status is the command's. That is the contract the Compose template of
#5 meets; the image's health probe is `keepia-mail healthcheck` (exit 0 when
`/healthz` answers 200), because the image has no curl. The tests use a fake
`docker` (`cmd/keepia-mail/km_test.go`).

Architecture and resource budget: [architecture.md](architecture.md).

## Security checks

The required checks are `secret-scan`, `links` and `workflows`. Each runs on
every pull request and every push to `main`; no workflow with a required job
has a `paths` filter.

```sh
make secrets-test secrets     # secret scan: self-test, then the full history
make links-test links         # Markdown links: self-test, then the repository
make workflows-test workflows # pin check: tests; then actionlint, pins, labels.json
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
- [`tools/check-action-pins`](../../tools/check-action-pins/main.go): every
  `uses` is pinned to a full 40-character commit SHA with a `# vX.Y.Z`
  comment (`owner/repo@<sha> # v1.2.3`); local actions (`./…`) are allowed,
  a `docker://` image needs an `@sha256:` digest. Its tests
  (`make workflows-test`) run it on the fixtures in
  `tools/check-action-pins/testdata/`;
- `jq empty .github/labels.json`: the label file is valid JSON.

**How the pin check reads the files.** It is a small Go tool that parses
YAML with `go.yaml.in/yaml/v3` and decides on the parsed node tree, not on
the text. It checks `.github/workflows/*.y*ml`, every `action.yml` and
`action.yaml` under `.github/actions` at any depth, and the action file of
every local action (`uses: ./path`) that a checked file names. Its rules:

- Every YAML document of a file is checked, not only the first. A file that
  does not parse is reported.
- Every mapping key that decodes to `uses` counts, wherever it sits: plain,
  quoted, escaped (`"u\x73es"`), explicit (`? uses`), inside an anchor that
  a merge key (`<<: *a`) or an alias uses, at job or step level. An anchored
  node is checked where its anchor defines it.
- An alias used as a mapping key (`- *k : …`) and a key with a tag other
  than `!!str` are reported, whatever they decode to. The tool does not
  resolve them; rejecting them fails closed.
- **Block style only.** A `uses` inside a flow mapping or flow sequence
  (`- {uses: …}`, `steps: [{uses: …}]`) is reported, also when it is pinned:
  in flow style the parser does not reliably attach the trailing comment to
  the value, so the version comment cannot be read there.
- The value must be a single-line string, plain or quoted. An alias
  (`uses: *x`), a block scalar (`>-`, `|`), another tag than `!!str`, an
  empty value, a mapping or a sequence is reported. The value may sit on
  the next line.
- The version comment is the value's own line comment: a real YAML comment
  after the value on its line. `# v7.0.1` inside a quoted value, on the key's
  line above the value, or on the next line does not count.

**What it does not check.** It does not check that the version comment
matches the SHA; that needs the network, and Dependabot keeps both in step.
A local action outside this repository, or a path that names no
`action.y*ml`, has nothing to scan. Known false positives, which fail
closed: any key named `uses` is checked, also one that is not an action
reference, such as a step input under `with:` or an env variable named
`uses`; rename it.

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
credential was a throwaway pull request, #12 (commit `fa639780b283a15081d58cc6fdeca130f46261d1`), closed
unmerged. Its only commit adds `proof/fake-token.txt` with the fake GitHub
token that `scripts/secret-scan-test.sh` builds at runtime (rule
`github-pat`); it is not a real credential. GitHub keeps that commit as
`refs/pull/12/head`, so a full-history rescan that includes `refs/pull/*`
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
