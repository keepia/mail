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
| `KEEPIA_DATABASE_URL` | none (required) | `serve`, `migrate`; holds the password and is never logged. URL form only: it must start with exactly `postgres://` or `postgresql://`, without spaces around it (the keyword/value form `host=… password=…` is rejected). Percent-encode `@`, `/`, `?` and `#` in the user or password and `@` in a query value (`%40`, `%2F`, `%3F`, `%23`); a URL that breaks these rules is rejected without showing any part of it |
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

## Images

The own images are defined once in
[`docker-bake.hcl`](../../docker-bake.hcl), for CI, `make images` and the
release (#5):

| Image | Dockerfile | Runs as | Health probe |
|---|---|---|---|
| `ghcr.io/keepia/mail` (Keepia) | [`Dockerfile`](../../Dockerfile) | 65532, no capabilities | `keepia-mail healthcheck` (`/healthz` 200) |
| `ghcr.io/keepia/mail-postfix` | [`images/postfix/Dockerfile`](../../images/postfix/Dockerfile) | root master with `CHOWN DAC_OVERRIDE FOWNER SETUID SETGID`, `chroot = n` everywhere | SMTP `220 ` greeting |
| `ghcr.io/keepia/mail-unbound` | [`images/unbound/Dockerfile`](../../images/unbound/Dockerfile) | 10053, no capabilities | `unbound-control status` |

Each Debian-based image lists its installed packages in
`/usr/share/keepia/packages.txt`; the Keepia image has none, because it is
distroless static and installs no Debian packages.

SOGo, olefy (#44) and the Compose template "all roles on one server" follow in
the next parts of #5; the upstream images (Dovecot, rspamd, ClamAV,
Postgres, Valkey, memcached) are used unchanged, pinned by digest in the
template.

```sh
make images                       # every image into the local Docker store, tag $(VERSION)
make image-test IMAGE=postfix     # smoke, health and reload tests of one built image
make image-pins-test image-pins   # the pin check: tests, then the repository
```

- **Pins.** Base images and the `# syntax=` frontend are pinned by tag and
  digest; downloads only by `ADD --checksum=sha256:`; Go modules by `go.sum`
  and `go mod verify`. Debian packages are not pinned (a superseded
  security version would leave the archive): each image records them in
  `/usr/share/keepia/packages.txt`, which CI prints.
- **Behind a TLS-inspecting proxy** (such as the agents' sandbox), set
  `KEEPIA_BUILD_CA` to a CA bundle file: `make images
  KEEPIA_BUILD_CA=/path/to/ca-bundle.crt`. The bundle reaches the build
  only as the BuildKit secret `ca`, never a layer; apt then fetches from the
  same Debian archive over https, and the build runs on the host network so
  `HTTPS_PROXY` (a predefined build argument, kept out of the image
  history) is reachable. `make images` runs `go run ./tools/check-image-pins
  -bake-local` with the typed options `-ca`, `-host-network` and
  `-https-proxy`, and the tool adds the matching `--set` and `--allow`
  arguments itself.
- **Reload watcher.** Postfix and Unbound start under `tini` with
  [`images/common/keepia-reload-watch`](../../images/common/keepia-reload-watch):
  when `/run/keepia/generation/` exists (the agent's read-only volume from
  0.2.0), a `generation` file written there (write, then rename) runs the
  image's reload command (`postfix reload`, `unbound-control reload`). The
  container exits when the service or the watcher stops, so a dead watcher
  cannot silently drop reloads (architecture section 5). Without the
  directory the service runs alone.
- **Image tests** ([`scripts/image-test.sh`](../../scripts/image-test.sh)):
  the smoke command; user, capabilities and `NoNewPrivs`; the healthcheck
  green, then red with every process of the container stopped (and, for
  Postfix, red with Debian's `chroot = y`, while `postfix status` still says
  running); the reload watcher (a write-and-rename from another container
  gives the reload line; killing `inotifywait` stops the container with
  status 1); and a clean `docker stop`. Every wait reads a Docker event or a
  log line, bounded by a timeout.

### The docker check

`ci.yml` has two jobs for the images. Both run on every pull request; the
`docker` job counts as required until the ruleset lists it (HANDOVER).

- **`docker-build (<image>, <arch>)`**: one row per image and platform,
  amd64 on `ubuntu-24.04` and arm64 on `ubuntu-24.04-arm`, natively (no
  QEMU). It points dockerd and BuildKit at `mirror.gcr.io` with Docker Hub
  as the fallback (`scripts/ci-docker-mirror.sh`). The build's bake inputs
  are defined once, in the job's env (`BAKE_TARGET`, `PLATFORM`,
  `BAKE_SET`). The step right before the build, `GOENV=off
  GOFLAGS=-mod=readonly GOWORK=off go run ./tools/check-image-pins -build
  "$BAKE_TARGET" -build-set "$BAKE_SET"`, resolves exactly those inputs in the build's
  environment and checks them (rule 5, build mode). The job then builds
  with `docker/bake-action` (`id: build`; it gives BuildKit the GitHub
  Actions cache: one scope per image and platform, written only by pushes
  to `main`). `go run ./tools/check-image-pins -verify-built` (`id:
  verify`) then compares each built image's local ID with the digest in
  the build's metadata and puts out the verified ID. The job runs
  `scripts/image-test.sh` on that ID, never on the tag. On amd64, `go run
  ./tools/check-image-pins -verify-built -save "$RUNNER_TEMP/image.tar"`
  verifies again, saves the image and checks the saved tar (one
  `manifest.json` and one `index.json` entry per name, naming the same
  config, with that config's layers), and the job
  uploads that tar for the `compose` job of #5 part 3 (artifact
  `image-<name>`, file `image.tar`, kept 1 day). CI never logs in to a
  registry and never pushes.
- **`docker`**: fails unless every `docker-build` row succeeded (a failed or
  cancelled row turns it red rather than skipped), then runs `make
  image-pins-test image-pins`.

The `lint` job also runs `scripts/check-go-toolchain-test.sh`; the
Dockerfile runs `scripts/check-go-toolchain.sh`, so the golang tag cannot
drift from `go.mod`'s `toolchain`.

`scripts/ci-docker-mirror.sh`, `scripts/ci-pull-images.sh` and
`scripts/check-go-toolchain.sh` (with its test) are byte-identical copies of
mail-archive's; change them there first. `ci-pull-images.sh` is used by the
`compose` job (#5 part 3).

### The image pin check

[`tools/check-image-pins`](../../tools/check-image-pins/main.go) walks the
repository and fails closed on any form it cannot read. The walk skips only
these root paths: `.git`, `bin`, `prototypes` (C10) and the checks' own
fixtures (`scripts/testdata`, `tools/*/testdata`). A directory with one of
those names elsewhere is walked. A Dockerfile that a bake target or a
Compose build names is always checked, whatever its name and wherever it
lives, also under a skipped path.

1. a Dockerfile's `# syntax=` is `name:X.Y.Z@sha256:<64 hex>`;
2. every `FROM`, `COPY --from=` and `RUN --mount=…,from=` names an earlier
   stage or `name:tag@sha256:<64 hex>`; `--mount` is read as one CSV record,
   as BuildKit does (so `"from=…"` counts); only `FROM --platform` may
   carry a variable (`$BUILDPLATFORM`, `$TARGETPLATFORM`); a `FROM` on
   several lines and a `--flag` on a continuation line are reported;
3. every `ADD` from `http(s)://` has `--checksum=sha256:<64 hex>`, one URL
   per `ADD`; `ADD` of a git URL (`git@`, `git://`, `ssh://`, `.git`, a
   `#ref`) and any `ADD` source with a variable (`$SRC`, `${SRC}`) are
   reported, because BuildKit expands variables in `ADD` sources;
4. a Compose file: a service without `build:` has `image:
   name:tag@sha256:<64 hex>`; a service with `build:` names its image
   under `${KEEPIA_REGISTRY…}` and builds from a relative local context.
   `build` may use only `context`, `dockerfile`, `args`, `target` and
   `labels` (so `x-bake`, `additional_contexts`, `dockerfile_inline`,
   `cache_from` and any new key are reported), and `args` may not set
   `BUILDKIT_SYNTAX`; a URL context, `extends` and `include` are reported;
5. the bake definition **exactly as each build resolves it**, never its HCL
   lines. In every resolved target:
   - only these keys may appear: `context`, `dockerfile`, `args`,
     `labels`, `tags`, `platforms`, `target`, and, as the mode allows,
     `cache-from`/`cache-to`, `secret`, `network` and `entitlements`.
     `output`, `ssh`, `call`, `attest` and any new key are reported;
   - `context` must be a relative path inside the repository;
   - named `contexts`, `dockerfile-inline` and a `BUILDKIT_SYNTAX`
     argument are reported;
   - every target's Dockerfile is read with rules 1–3.

   The check is part of every build invocation.
   - **Local mode** (`-bake-local`, the only local build path; `make
     images`):
     - The tool builds the bake argument list itself: the root's default
       files with `--file`, and `--set` lines only from its typed options.
       `-ca` gives the secret `id=ca` and `--allow fs.read`;
       `-host-network` gives `network=host` and `--allow network.host`;
       `-https-proxy` gives `args.HTTPS_PROXY`.
     - It uses a cleaned environment plus `VERSION`, `REGISTRY` and
       `PLATFORM` from `-version`, `-registry` and `-platform`.
     - It resolves `--print` with exactly that, checks it, and then runs
       `docker buildx bake --load` with the same arguments and environment.
       It looks the docker CLI up in `PATH` once and runs that absolute
       path for both. No cache is allowed. `-dry-run` prints the command
       instead of building.
   - **Build mode** (`-build`, CI): resolves the build step's targets, `--set`
     lines and environment, as described below. The cache may only be
     `type=gha` with this row's scope (`<target>-<arch>`, from `PLATFORM`)
     and no other key: a foreign cache would stand in for build steps by
     their cache keys.
   - **Verify mode** (`-verify-built`, CI): the images a job tests and saves
     are the checked build's output.
     - It reads bake-action's metadata output (`BAKE_METADATA`) and
       compares every image name's local ID with the digest the build
       reported: `containerimage.digest` for Docker's containerd store, or
       `containerimage.config.digest` for the classic store.
     - Any other build, `docker tag` or `docker load` in between fails it.
     - It only proves the store's state while it runs, so nothing after it
       goes by tag. In GitHub Actions it puts out the verified image ID as
       the step output `image`, and the test runs that ID. `-save FILE`
       saves the verified names itself, then checks the tar: every blob's
       content matches its digest, and each name's config is the build's
       config, or its index entry is the build's digest and names that
       config. Only then is the tar renamed to `FILE`.
   - **Repository mode** (`make image-pins`):
     - The tool passes every one of buildx's default files present at the
       root to `docker buildx bake` with `--file`, in buildx's order:
       `compose.yaml`, `compose.yml`, `docker-compose.yml`,
       `docker-compose.yaml`, `docker-bake.json`, `docker-bake.hcl`,
       `docker-bake.override.json`, `docker-bake.override.hcl`. A Compose
       file alone counts too.
     - It runs bake in a cleaned environment: only `PATH`, `HOME`,
       `DOCKER_CONFIG`, `DOCKER_HOST` and `DOCKER_CONTEXT` (what the CLI
       needs to find its plugin and daemon), so no `BUILDX_*` and no bake
       variable from the caller. Local mode uses the same environment.
     - Target names come only from `--list` and are passed after `--`.
       Hidden targets are checked through the targets that inherit them.
     - It then resolves again with every declared variable at a sentinel
       value. A target whose `context`, `contexts`, `dockerfile`,
       `dockerfile-inline` or `BUILDKIT_SYNTAX` moves is reported, because
       a build's environment could move it. Known variables have sentinels
       that still resolve (`PLATFORM` must be a platform). If the definition
       does not resolve with the sentinels, the check fails.
     - This mode is best effort. One sentinel value per variable cannot
       show a condition on another value, and a `timestamp()` condition
       fires only on its day. The local and build modes are authoritative,
       because they check what is actually built.
   - **Build mode in CI**: the exact targets (`BAKE_TARGET`), `--set` lines
     (`BAKE_SET`) and environment of the build step that follows it, with
     buildx's own file lookup.
   - **Every build input is visible to the check.**
     - In workflows, a job builds images only through one
       `docker/bake-action` step:
       - inputs only `source: .`, `targets: ${{ env.BAKE_TARGET }}`,
         `set: ${{ env.BAKE_SET }}`, `load`, `push`, `no-cache` and `pull`
         (no `files`, `workdir` or `vars`, and no `sbom` or `provenance`:
         their values become attestations that build mode never resolves,
         such as an unpinned SBOM generator image), and `id: build`;
       - no step env, and job and workflow env only `BAKE_TARGET`,
         `BAKE_SET` and `PLATFORM`, whose expressions may read only
         `matrix.*` and `github.event_name`;
       - `BAKE_SET` lines may set only `cache-from` and `cache-to`, and a
         literal cache value must be `type=gha`;
       - the step right before is exactly `run: GOENV=off
         GOFLAGS=-mod=readonly GOWORK=off go run ./tools/check-image-pins
         -build "$BAKE_TARGET" -build-set "$BAKE_SET"`, with no env, `if`
         or `continue-on-error`. The verify step is `run: GOENV=off
         GOFLAGS=-mod=readonly GOWORK=off go run ./tools/check-image-pins
         -verify-built`, optionally with `-save "$RUNNER_TEMP/<name>.tar"`.
         The prefix builds the tool from the module and the checked module
         cache alone: an empty `GOFLAGS` alone would fall back to the go
         env file, and without `-mod=readonly` a `vendor/` directory an
         earlier step creates would replace its dependencies;
       - every step of the job runs only what the check can read. It
         follows a step's scripts by their repository path, also written
         as `$GITHUB_WORKSPACE/…` or `${{ github.workspace }}/…`, under
         `working-directory:` or after `cd` (a relative path is followed
         in every directory it may run in), as `$(dirname "$0")/…`
         inside a script, and as `$GITHUB_ACTION_PATH/…` or `${{
         github.action_path }}/…` in a composite action; `make <target>`
         (the target's recipe and prerequisites, with the Makefile's
         variables and literal includes, plus the whole Makefile and its
         includes as text); local actions, nested ones included; and the
         `script` of `actions/github-script`. A script run by `python`,
         `node` and other non-shell interpreters is read only for image
         commands, and a file that is not text is not read. A step that
         runs a script path it cannot resolve this way (a variable, a
         command word that is a variable such as `"$SAVE"` or the body of
         `sh -c "$CMD"`, an absolute path outside `/usr`, `/bin` and
         `/sbin`, a missing file or a binary, a make target without an
         explicit rule, a prerequisite with neither rule nor file, or a
         Makefile that uses a conditional, `define`, `.DEFAULT_GOAL`,
         `$(eval)` or `$(call)`), or that names more than 200 files, is
         reported;
       - no step of the job writes `GITHUB_ENV` or `GITHUB_PATH` (in what it
         runs, as above, or with `core.exportVariable`/`core.addPath` in a
         github-script), except the commit time (`SOURCE_DATE_EPOCH`) and
         the anonymous `DOCKER_CONFIG` of `scripts/ci-docker-mirror.sh`;
       - the step right before every step after the build that runs
         `image-test`, `docker save`, `push` or `tag`, Compose push,
         `buildx imagetools create`, crane or skopeo (also in what it runs)
         is a verify step with the same `if`;
       - a step that runs `image-test` tests the verified ID: env
         `VERIFIED_IMAGE: ${{ steps.<id of that verify step>.outputs.image
         }}`, and every call is `scripts/image-test.sh <name>
         "$VERIFIED_IMAGE"`, the argument the script tests (`make
         image-test` tests the Makefile's tag);
       - no `docker save` after the build: the save is verify's own
         `-save`;
       - after the build, an image leaves the runner only as `docker tag
         "$VERIFIED_IMAGE" <name>` and `docker push <name>` in the same
         step (with the same env); Compose push, `buildx imagetools
         create`, crane and skopeo are reported.
     - **Other build paths are reported** (defence in depth; verify mode is
       the real guarantee):
       - `docker`, `podman` and `nerdctl` `build`, `image build` and
         `builder build`; `buildx build`/`bake`/`b`; Compose builds
         (`compose build`, `compose watch`, any `compose` subcommand with
         `--build` or `--build=…`, `up` and `create` without
         `--no-build`, which build every service that has `build:` and no
         image yet, and every `run`: Compose's `run` has no `--no-build`,
         so start services with `up -d --no-build` and use `exec`; also
         `docker-compose`, `podman-compose`); `buildctl`;
         and `buildah build`. They are matched word by word after quotes
         and backslashes are removed (`ba""ke` matches), with global
         options before a subcommand skipped (`docker --context x build`,
         `docker buildx --builder b build`), and words also end at `,`,
         `[` and `]`, so a list in Python or another language
         (`["docker", "build", "."]`) matches too, also when it is split
         over lines inside `(` or `[`, as black and gofmt write it;
       - in workflow `run:` steps, `actions/github-script` scripts,
         composite actions under `.github/actions/`, `*.sh` files, and any
         file a workflow, action or Makefile names in a command (`sh
         scripts/build`);
       - any build action in `uses:` (`docker/build-push-action`, other
         `docker/*` actions except the setup, login and metadata ones,
         `bake-action` outside the allowed step);
       - a job that calls a remote reusable workflow.
     - A Makefile or `*.mk` file holds no `buildx` and no `BUILDX_` at all
       (after quotes are removed), and no other build command. It does not
       set or export `PATH` or `HOME`, and names no `DOCKER_CONFIG`,
       `DOCKER_HOST` or `DOCKER_CONTEXT`: local mode passes these to docker,
       and make passes its own value of an environment variable to a
       recipe even without `export`. It also sets no `SHELL` or
       `.SHELLFLAGS`, sets or exports no `GOFLAGS`, `GOENV` or `GOWORK`,
       and sets `GO` only to `go` (`make images` runs `$(GO) run
       ./tools/check-image-pins`); it includes only literal `*.mk` files
       the check reads; and it computes no variable name (`export
       PA$(E)TH`).
   - Any `*.hcl` other than the root's `docker-bake.hcl` and
     `docker-bake.override.hcl` is reported, unless it is on the tool's
     `hclAllowlist`, which is empty. A JSON bake file is reported;
6. no workflow except `release.yml` grants `packages: write`, at workflow or
   job level; `permissions: write-all`, a job that calls a reusable
   workflow without its own `permissions`, and a job without permissions in
   a workflow without them are reported. In every workflow, `release.yml`
   included, each job's `container` and `services` image is
   `name:tag@sha256:<64 hex>`.

**Threat model.**
- The check catches accidental unpinned references and fails closed on
  forms it cannot resolve. In a job that builds, that includes the
  scripts a step runs: the check does not model every shell form, but a
  script path it cannot resolve to a file in the repository is reported,
  not skipped.
- The local and build modes are authoritative, together with verify mode in
  CI: they check what is actually built, with the real environment.
- Repository mode is best effort for value-conditional HCL expressions.
  Its known limits are the single-value sentinel and `timestamp()`
  conditions.
- Verify mode proves the store's state only while it runs, so nothing
  after it goes by tag: the test runs the verified image ID, the save
  checks the tar it wrote, and a push pushes a name the same step tagged
  from the verified ID (a re-tag between those two commands is deliberate
  and for review). The saved tar is checked as both image stores load it:
  one `manifest.json` and one `index.json` entry per name, naming the same
  config, with that config's layers. The check and verify steps build the
  tool with `GOENV=off GOFLAGS=-mod=readonly GOWORK=off`, and the build
  job may not write `GITHUB_ENV` or `GITHUB_PATH` otherwise, so an earlier
  step cannot reroute the tool's own build; locally the Makefile may not
  set `SHELL`, `GO` or the Go variables the tool is built with.
- A pull request that edits the check itself, or deliberately disables or
  routes around it (for example a build command assembled at run time, or
  a process started earlier that changes the image store or a file
  later), is the reviewers' responsibility, not the tool's. The rule file
  `.claude/rules/docker.md` says so as well.

**Rule 5 needs Docker.** It runs the `docker` CLI with the buildx plugin
(no daemon needed; buildx resolves the file itself). Without it, `make
image-pins` reports "cannot resolve the bake definition" and fails: it
never passes a bake file unread. CI's `docker` job runs on a runner with
Docker.

It also reports here-documents and `ONBUILD` in Dockerfiles. Downloads in
`RUN` are a review rule (`.claude/rules/docker.md`), not a heuristic. Its
tests run it on the fixtures in `tools/check-image-pins/testdata/`:
single files per rule (a fail fixture names its expected lines in its last
line, `# want-lines: N`), and whole trees in `testdata/repos/` with the
expected findings in `WANT`. The trees with a bake file need buildx: they
skip locally without it and fail in CI (`CI` set).

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

- Dependabot opens weekly update pull requests for Go modules, GitHub
  Actions and the images' base images and frontend (`docker`, for the root
  `Dockerfile` and each `images/<name>/`) (`.github/dependabot.yml`). It
  waits 14 days after a release
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
