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
`./km migrate`. The local flow is:

```sh
make images      # build the images, the only local build path
./km migrate     # then run keepia-mail commands
```

`km` never builds (#56), so a CI job can run it without a second, unchecked
build path. The only images it pulls are upstream images pinned by digest,
and it pulls them by that digest. In order:

1. If no Docker daemon is reachable, it stops with docker's own error.
2. It lists the images of the Compose services `postgres` and `keepia` and
   of every service they depend on (`docker compose config --images
   postgres keepia`). It checks that each image is in the local Docker
   store. Nothing has been started yet. For a missing image:
   - an upstream image pinned by digest (`…@sha256:…`) is pulled by that
     digest (`docker pull -q -- <image>`), which is content-addressed. If
     the pull fails, km exits non-zero with docker's error and the image;
   - for any other image, km exits non-zero and names the image and `make
     images`.
3. It starts `postgres` (`docker compose up -d --wait --no-build --pull
   never postgres`) and `keepia` (`docker compose up -d --no-build --pull
   never keepia`). Every image, including those of all dependencies, is in
   the local store by now, so neither call builds or pulls.
4. It runs the command in the running container (`docker compose exec -T
   keepia keepia-mail …`). Its exit status is the command's.

That is the contract the Compose template of #5 meets; the image's health
probe is `keepia-mail healthcheck` (exit 0 when `/healthz` answers 200),
because the image has no curl. The tests use a fake `docker`
(`cmd/keepia-mail/km_test.go`).

- **Image names:** `keepia`'s `image:` in the Compose file must equal the
  tag `make images` gives it, `$(REGISTRY)/mail:$(VERSION)`. `VERSION`
  defaults to `git describe --tags --always --dirty`, so the Compose file
  needs a variable for the tag, or `make images VERSION=…` must match the
  Compose file's default. A service with only `build:` resolves to
  `<project>-keepia` and never matches: `km` then reports it missing.
- **A crash-looping `keepia`:** `exec` needs a running container. If
  `keepia` keeps restarting (for example, `serve` exits on a failed
  migration), `km` fails, mostly with "Container … is restarting". When
  its exec meets a run of `keepia` just as that run exits, the message
  comes from the runtime instead (for example "cannot exec in a stopped
  container", or exit 137 and none at all). Read `docker
  compose logs keepia`, fix the cause, then start it again with `docker
  compose up -d --no-build --pull never keepia`.

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
| `ghcr.io/keepia/mail-olefy` | [`images/olefy/Dockerfile`](../../images/olefy/Dockerfile) | 10055, no capabilities | olefy's `PING` answered by `PONG` |
| `ghcr.io/keepia/mail-sogo` | [`images/sogo/Dockerfile`](../../images/sogo/Dockerfile) | 10060, no capabilities | `GET /SOGo/` answered by an HTTP status line |

Each Debian-based image lists its installed packages in
`/usr/share/keepia/packages.txt`; the Keepia image has none, because it is
distroless static and installs no Debian packages.

olefy's source is one pinned commit of HeinleinSupport/olefy (the project
has no release tags), fetched as GitHub's commit archive with
`ADD --checksum`; the build checks that the archive holds exactly that
commit's tree ([`images/olefy/olefy-source.sha256`](../../images/olefy/olefy-source.sha256)).

SOGo is built from Alinto's release tags: SOPE and SOGo of the same
release, each fetched as GitHub's tag archive with `ADD --checksum`, then
compiled in a build stage with Debian's build dependencies. Their trees
have thousands of entries, so their manifests
([`images/sogo/sope-source.sha256`](../../images/sogo/sope-source.sha256),
[`images/sogo/sogo-source.sha256`](../../images/sogo/sogo-source.sha256))
pin the sha256 of the tree's listing instead of the listing itself.

[`images/common/check-source`](../../images/common/check-source) unpacks
the archive (umask 022, `--no-same-permissions`, so no setuid, setgid,
sticky or group- or world-writable entry lands) and compares its listing
with the manifest: every file with its mode and sha256, every directory
(also an empty one, such as a submodule's), and nothing else.
[`scripts/source-listing.sh`](../../scripts/source-listing.sh) writes the
same listing from a clone; `make image-scripts-test` tests both.

To move a pin, compute the archive's sha256 and the tree's listing offline
from a clone of the public repository, never from a download, and update
the Dockerfile and the manifest together. GitHub's archives are
`git archive` with GitHub's prefix, compressed by an external
`gzip -cn` (git's internal gzip gives other bytes). Run the commands in a
scratch directory outside the work tree, so the clone and the archive do
not land untracked in it; `<repo>` stands for the work tree's path. For
olefy at a new commit `<c>`:

```sh
cd "$(mktemp -d)"
git clone --bare https://github.com/HeinleinSupport/olefy.git olefy.git
git --git-dir=olefy.git -c tar.tar.gz.command="gzip -cn" archive --format=tar.gz \
  --prefix=olefy-<c>/ -o olefy.tar.gz <c>
sha256sum olefy.tar.gz                                   # the ADD --checksum
bash <repo>/scripts/source-listing.sh olefy.git <c>      # the manifest's lines, after its comments
```

For SOPE and SOGo at a new release `<v>`, for each of `sope SOPE` and
`sogo SOGo` (shown for SOGo), also in a scratch directory:

```sh
cd "$(mktemp -d)"
git clone --bare https://github.com/Alinto/sogo.git sogo.git
git --git-dir=sogo.git -c tar.tar.gz.command="gzip -cn" archive --format=tar.gz \
  --prefix=sogo-SOGo-<v>/ -o sogo.tar.gz SOGo-<v>
sha256sum sogo.tar.gz                                    # the ADD --checksum
bash <repo>/scripts/source-listing.sh sogo.git SOGo-<v> >sogo-listing.txt
sha256sum sogo-listing.txt; wc -l <sogo-listing.txt      # the manifest's "listing <sha256> <count>"
```

`--git-dir` keeps `-o` relative to the current directory (`git -C` would
write the archive into the clone). The listing reads `git ls-tree -r -t -z`,
so any path name comes out unquoted. On a mismatch the build prints the
archive's listing (or, for olefy, a diff), so a `diff` against
`sogo-listing.txt` names the entry.

The upstream images (Dovecot, rspamd, ClamAV, Postgres, Valkey,
memcached) are used unchanged, pinned by digest in the Compose template
below.

```sh
make images                       # every image into the local Docker store, tag $(VERSION)
make image-test IMAGE=postfix     # smoke, health and reload tests of one built image
make image-pins-test image-pins   # the pin check: tests, then the repository
make image-scripts-test           # check-source, source-listing.sh, keepia-sogod, edge guard, km failure cause (no Docker, no network)
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

### The Compose template

[`docker-compose.yml`](../../docker-compose.yml) holds every role, one
profile each (architecture section 7); with
`COMPOSE_PROFILES=control,edge,store,filter,groupware` it is the template
"all roles on one server": 14 containers, plus the one-shot
`edge-addresses`, which exits once it has checked the edge addresses. It
needs Docker Engine 28 or later (the gateway mode `isolated`): Engine 27
refuses to create the networks, and 26 or older creates them without the
isolation, silently. [Architecture section 7](architecture.md#7-docker)
has the check to run after the first start: the host must have no
address in the internal subnets (`edge-public`, which is not internal,
keeps its gateway address on the host).

```sh
cp .env.example .env              # then set KEEPIA_POSTGRES_PASSWORD and the edge addresses
make images VERSION=dev           # the own images, tagged as .env's KEEPIA_VERSION
docker compose up -d --wait --no-build --pull never
./km migrate status
```

| Role | Containers | Network (internal) |
|---|---|---|
| control | `keepia`, `postgres`, `valkey`, `control-unbound` | `control-private` |
| edge | `edge-postfix`, `edge-dovecot`, `edge-unbound` | `edge-private`; `edge-postfix` also on `edge-public`, the only network with a way out |
| store | `store-dovecot` | `store-private` |
| filter | `filter-rspamd`, `filter-clamd`, `filter-olefy`, `filter-unbound` | `filter-private`; `filter-olefy` (olefy has no authentication) holds only rspamd and olefy |
| groupware | `groupware-sogo`, `groupware-memcached` | `groupware-private` |

- **Only port 25 is published**, to `EDGE_IPV4` and `EDGE_IPV6`; outbound
  mail is SNATed to them. A wildcard there (`0.0.0.0`, `::` or another
  spelling of them) is refused by
  [`deploy/edge/check-edge-addresses.sh`](../../deploy/edge/check-edge-addresses.sh),
  in two places. On `up`, the one-shot `edge-addresses` runs it, and
  `edge-postfix` starts only after it exited 0, so a refused `up`
  publishes nothing; it leaves `edge-postfix` Created with the wildcard
  in its port bindings. A start that skips that dependency (`docker
  compose restart`, `docker start`, `up --no-deps`) reaches the second
  place, `edge-postfix`'s own entrypoint, which exits 1 before Postfix
  runs. Docker publishes the port for that moment (and for each restart
  attempt): docker-proxy can briefly accept a TCP handshake, but nothing
  in the container listens and no data is handled (measured: 8 of 6468
  probes accepted, no `220` banner). After a refusal, fix `.env`, then
  run `docker compose rm -f edge-postfix` and `up` again. The check is in
  Compose and not in `km`, because `km` never starts the edge role.
- **The host cannot reach the internal networks:** their bridges use the
  gateway mode `isolated` and have no host address, so host processes
  cannot reach memcached, olefy, clamd or rspamd (no authentication), and
  containers cannot reach host services through a bridge. Debugging from
  the host therefore goes through `docker compose exec` or a helper
  container on the network. In 0.1.0 no traffic crosses roles (the gates
  come with 0.2.0), Postfix has no domains (`454 4.7.1`, deferred), the
  edge Dovecot answers every lookup with a temporary failure, and every
  Unbound refuses everything but its health zone.
- **Every container** drops all capabilities, runs with
  `no-new-privileges` and a fixed non-root uid (Postfix's master aside),
  has its memory limit (architecture section 9), a process limit
  (`pids_limit`), a protocol healthcheck, and fixed addresses; it listens only on them or on loopback
  (R-BIND-PRIVATE). Programs that read their address from the
  environment or the command line (Keepia, Postgres, Valkey, memcached,
  rspamd, olefy, SOGo) keep a read-only root file system. Postfix,
  Dovecot, ClamAV and Unbound read it only from their configuration, so a
  `configs:` entry with the address is mounted there, which Compose does
  not allow on a read-only root.
- **Static configuration** lives in [`deploy/`](../../deploy)
  (`deploy/<role>/<service>/`); the agent replaces it in 0.2.0.
- **Volumes** are named; every image `VOLUME` is covered, so Compose
  creates no anonymous volume. The nine are `postgres-data`,
  `valkey-data`, `postfix-spool`, `edge-vmail` (stays empty),
  `store-mail`, `store-index`, `store-users`, `rspamd-data` and
  `sogo-spool`. Mail is in `store-mail` at exactly `/srv/vmail`, the
  indexes in `store-index`.
- **Logs** go to journald (`KEEPIA_LOG_DRIVER`, `local` on a host without
  it); the host keeps them 30 days.
- **Own image names:** `${KEEPIA_<NAME>_IMAGE:-${KEEPIA_REGISTRY}/mail-<name>:${KEEPIA_VERSION}}`
  (`KEEPIA_IMAGE` for Keepia). The registry name is the tag `make images`
  gives; the variable in front replaces it with an image ID, which the
  `compose` job uses. An own image is never pinned by digest here, or
  `km` would pull it. Each also names its `build:` definition (the same as
  `docker-bake.hcl`'s), but the template is only used with `--no-build`.
- **No IPv6 on the host** (such as the agents' sandbox): the networks and
  `edge-postfix`'s `main.cf` need IPv6. A local run there needs an
  untracked override file (`COMPOSE_FILE=docker-compose.yml:<override>`)
  that drops the IPv6 subnets and addresses with `!reset`/`!override`.

[`scripts/compose-test.sh`](../../scripts/compose-test.sh) starts the
template (`up -d --wait --no-build --pull never`) and checks it. First, a
start with `EDGE_IPV4=0.0.0.0` and then `EDGE_IPV6=::` must fail in
`edge-addresses` without `edge-postfix` ever running, and a `docker
start` of the `edge-postfix` that the refusal left behind must exit 1 on
its own check, before Postfix (test 14). Then:
exactly the 14 containers, each with a healthcheck and healthy, the guard
exited 0, and an olefy scan (test 6); every listening socket either on
loopback or exactly one of the container's planned listeners (protocol,
address and port), each planned one present, none on 8080/9090 in Dovecot, read by a
helper container in the container's network namespace (test 8); the
networks, their gateway mode `isolated`, no host address in them, no host
reach to rspamd, clamd, olefy or memcached while a container on the
network reaches them, the fixed addresses and the only published port
(test 9); capabilities, `no-new-privileges`, `pids_limit` and uids (test
10); a message over LMTP into the named volume `store-mail`, an empty
`edge-vmail` and no anonymous volume (test 11); the edge's `451 4.3.0`
and `NO [UNAVAILABLE]` (test 12); and the edge SNAT and DNAT rules (test
13). It runs every test and names each failure; every helper run is
bounded by a timeout. It still needs sudo for the NAT rules (test 13) and,
in CI, to put the edge addresses on loopback.

### The docker check

`ci.yml` has three jobs for the images. All run on every pull request; the
`docker` and `compose` jobs count as required until the ruleset lists them
(HANDOVER).

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
  uploads that tar with the build's metadata for the `compose` job
  (artifact `image-<name>`, files `image.tar` and `metadata.json`, kept 1
  day). CI never logs in to a registry and never pushes.
- **`docker`**: fails unless every `docker-build` row succeeded (a failed or
  cancelled row turns it red rather than skipped), then runs `make
  image-pins-test image-pins`.
- **`compose`**: fails the same way unless every `docker-build` row
  succeeded. It pulls the upstream images by digest
  (`scripts/ci-pull-images.sh`), downloads the five amd64 artifacts and
  `docker load`s them: no second build. For each image, `-verify-built`
  with that build's `metadata.json` checks the loaded image and puts out
  its ID; the later steps give Compose these IDs (`KEEPIA_IMAGE`,
  `KEEPIA_POSTFIX_IMAGE`, `KEEPIA_UNBOUND_IMAGE`, `KEEPIA_OLEFY_IMAGE`,
  `KEEPIA_SOGO_IMAGE`), so nothing after the verification goes by tag. Then
  `scripts/compose-test.sh` (tests 6 and 8–14), `./km migrate` and `./km
  migrate status` (test 7: version 1 applied), `./km` with a wrong database
  password (it must fail at its exec, and `scripts/km-failure-cause.sh`
  names why: the exec found the recreated keepia restarting, met a run of
  it as that run exited, or migrate's own login failed with SQLSTATE
  28P01; a failure before the exec, a crash of keepia-mail (exit 2, a
  Go panic or fatal error) or any other keepia-mail error fails the step.
  Any other failure at the exec counts as the restart loop, so an
  intermittent Docker or Compose exec failure would pass too; a
  systematic one fails the `./km migrate` step before. That keepia is
  still running or restarting, has restarted, and its log has SQLSTATE
  28P01), and `docker
  compose down --volumes`. The step
  summary lists each container's health, memory and CPU.

The `lint` job also runs `scripts/check-go-toolchain-test.sh`; the
Dockerfile runs `scripts/check-go-toolchain.sh`, so the golang tag cannot
drift from `go.mod`'s `toolchain`. It then runs `make image-scripts-test`,
the tests of `images/common/check-source`, `scripts/source-listing.sh`,
`images/sogo/keepia-sogod`, the edge address guard and
`scripts/km-failure-cause.sh` (test 7's counter-case), without Docker or
network.

`scripts/ci-docker-mirror.sh`, `scripts/ci-pull-images.sh` and
`scripts/check-go-toolchain.sh` (with its test) are byte-identical copies of
mail-archive's; change them there first. `ci-pull-images.sh` is used by the
`compose` job.

`scripts/next-version.sh` is byte-identical with pklnx/mail-archive's at
`b312d9f` (sha256 `948fc5e2a6117815f6e67859d86c7ac36ae0c471f7103313aea9ccc437ef248e`,
unchanged since `86ad8b8`); change it there first. mail-archive's
`next-version-test.sh` (sha256
`b14e390052d0bf86b9510a962867c987983c65a4e08ea11374fcc6da95b6bcf2`) is not
vendored: its last sections test mail-archive's own release-bundle and
release-notes scripts, so it cannot pass here. Instead
`scripts/version-policy-test.sh` (test 14) covers the `next`, `last`,
`base`, `pr` and `summary` behaviour Keepia relies on, besides the 0.x
rules of `scripts/version-policy.sh`.

**Release scripts** (#27; `make release-scripts-test` in the `lint` job,
no network, no daemon): `scripts/version-policy.sh LAST INPUT < prs.tsv`
(the 0.x rules over `next-version.sh`: a virtual last version `0.0.0` for
the first release, and `breaking` raises the minor version before 1.0),
`scripts/release-bundle.sh VERSION OUTDIR DIGESTS [SOURCES_MD]` (the bundle
`keepia-mail-VERSION.tar.gz`: Compose with every own image as
`${KEEPIA_<NAME>_IMAGE:-ghcr.io/keepia/mail-<name>:VERSION@sha256:…}` and no
`build:`) and `scripts/release-notes.sh VERSION LAST DIGESTS LICENCES`.
`tools/release-sources` (standard library only; test 21 in `go test`)
writes each row's SBOM and source list and the release's `sources.json`
and `SOURCES.md`. The `compose` job starts the bundle with the verified
images in its own project (test 15b).

Every SBOM package that is neither a Debian package nor a Go module
(syft's `python` and `npm` packages, #73) must be part of a component of
its row, or the row fails. Such a package needs at least one location, each
an absolute path; then the first rule that holds covers it:

1. a Debian package of the SBOM owns it: syft's `ownership-by-file-overlap`
   relationship from that deb, and every location in the deb's file list
   (by path, not content: nothing but `keepia-apt-install` writes under
   `/usr/lib/python3`);
2. it is a pinned wheel: name (PEP 503) and version of a PyPI-wheel `ADD`,
   installed from that file (`direct_url.json` is a `file:///` URL with
   the `ADD`'s file name);
3. the vendored path table (`vendored` in `tools/release-sources/main.go`,
   reviewed like `addLicences`) names it: today SOGo's npm packages under
   `/usr/lib/<triplet>/GNUstep/SOGo/WebServerResources/`, part of the SOGo
   archive. A new `COPY` or `RUN` that writes under a table prefix needs
   the table's evidence checked again (the installed tree is identical to
   the archive's), and so does a move of the SOGo pin, together with the
   CKEditor paragraph of `SOURCES.md`.

`sources.json` and `SOURCES.md` list these packages with the component they
are part of. The rules read syft's `locations`, deb file lists,
`artifactRelationships` and `directUrlOrigin` at the pinned v1.57.1, and
fail closed if one disappears: a syft bump re-runs all rows locally first.
The fixtures in `tools/release-sources/testdata` are real syft output of
the olefy and sogo images, trimmed with the jq filter quoted in
`fixture_test.go`.

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
   exactly `${KEEPIA_REGISTRY:-ghcr.io/keepia}/mail[-<name>]`, with an
   optional tag that is literal or `${KEEPIA_VERSION:-<tag>}` (the whole
   name is matched, so `${KEEPIA_REGISTRY:-docker.io/…}` or
   `${KEEPIA_REGISTRYX:-…}` fails, #61), or as
   `${KEEPIA_<NAME>_IMAGE:-<that name>}` (a variable that replaces the
   whole name, in CI with the verified image ID), and builds from a
   relative local context.
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
         reported. An exception may skip a word, never a whole command: a
         variable the script sets only to plain command names (`SUDO=sudo`)
         is replaced by its value and the command read again; `"$@"` or
         `"$N"` as a command is skipped only inside a function body, where
         the arguments are words of the same text. At a script's top level
         it forwards the caller's arguments as a command, which the check
         does not model (`shift`, `set --`, forwarding through more
         scripts): it is reported, and the fix is to call the command
         directly. A call at the top level that passes its arguments
         (`"$@"`, `"$*"`, `"$N"`, also with any operator such as
         `${1+"$@"}` or `"${1?msg}"`), or any other variable or command
         substitution (`"${args[@]}"`, `$cmd`), to a function whose body
         runs its positional parameters as a command word is reported in
         the same way (#67):
         the `main` idiom `main() { for i in 1 2 3; do "$@" && return 0;
         done; return 1; }; main "$@"`, also with a `while` loop, `shift`
         before the call or in the body, a prefix such as `exec` or
         `sudo`, or a function that passes them on to such a function
         (defined inside it or not, through any number of functions),
         also as a copy made in a body: an array expansion
         (`local args=("$@"); retry "${args[@]}"`) or a variable some
         function body assigns from `$@`/`$*` (`local c="$*"; run $c`,
         `read -r -a a <<< "$*"`). A plain data variable passed on in a
         body (`"$c"` with `c=$1`) does not count. When the reported
         argument is not a positional parameter, the finding says the
         call passes it to a function that runs its arguments as a
         command;
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
6. no workflow except `.github/workflows/release.yml` (exactly that path,
   in that case: a `release.yaml` or `Release.yml` is a workflow like any
   other) grants `packages: write`, at workflow or
   job level; `permissions: write-all`, a job that calls a reusable
   workflow without its own `permissions`, and a job without permissions in
   a workflow without them are reported. In every workflow, `release.yml`
   included, each job's `container` and `services` image is
   `name:tag@sha256:<64 hex>`, and so is the BuildKit image of every
   `docker/setup-buildx-action` step (`driver-opts: image=…`, the
   docker-container driver only, and no input but `driver-opts`,
   `buildkitd-config-inline` and `driver`, so no `append`, `endpoint` or
   `version`): without it the builder runs the floating
   `moby/buildkit:buildx-stable-1`, and in `push` that container holds the
   GHCR credentials (#71 review B, N6);
7. **the release surface** (#27,
   [`release.go`](../../tools/check-image-pins/release.go)): `release.yml`
   has exactly the planned shape, so the one workflow that can push cannot
   grow a second push path. The policy is data in the tool:
   - **P2, P6:** exactly the jobs `version`, `build`, `push-rehearsal`,
     `push`, `index`, `bundle`, `attest`, `attest-assets`, `release` and
     `latest`, each with exactly its permissions, `needs` and `if`
     (top-level `permissions: {}`; `packages: write` only in `push`,
     `index` and `latest`, all with `${{ !inputs.dry_run }}`), and no job
     `uses:`;
   - **P3, P4, P5, P9:** in `push`, `push-rehearsal`, `index` and
     `latest`, every step is exactly the policy's step at its position: an
     action of the job's list (checkout, setup-go, setup-buildx with CI's
     inputs, the `tested-*`/`digest-*` artifacts, bake-action once in the
     push jobs) at the policy's own commit (`actionPins`, CI's pins), with
     exactly its inputs, or a run step whose trimmed text
     equals one fixed line (`SOURCE_DATE_EPOCH`, the GHCR login, `-build`,
     `-verify-pushed`, `-publish-index`, `-move-latest`) with exactly its
     env and no `if`, `shell`, `working-directory` or `continue-on-error`.
     Nothing is resolved, so these jobs run no repository script, make
     target or other `go run`, define no shell function and run no
     `eval`, `sh -c`, `source` or `xargs` (the findings name the form).
     `push-rehearsal` is `push` without the login and with `push=false`.
     The bake jobs' `BAKE_SET` holds exactly the release cache line, and in
     the push jobs the two outputs (`type=image,push-by-digest=true,
     name-canonical=true,push=true|false` and `type=oci,dest=pushed.tar`)
     and `attest=type=provenance,mode=max`; build mode checks what they
     resolve to, the target's tags `ghcr.io/keepia/mail[-<name>]:VERSION`
     and `VERSION` as X.Y.Z, and refuses a `pushed.tar` that exists in any
     form. A script allowlisted for these jobs (none) may have no
     forwarding function;
   - **`attest`, `attest-assets` and `release` have exact steps too**
     (#27 part 4b, #71 review B N2), the same way: the `dist` and `digest-*`
     artifacts, `sha256sum -c SHA256SUMS` in `dist`, `attest`'s subjects
     step (the index digests from `index`, the platform manifests from the
     push rows' digest files, each checked as `sha256:<64 hex>`), one
     `actions/attest` step per subject (the provenance of each image's
     index, the SBOM of each platform manifest, every release asset), and
     `release`'s tag, release and cleanup steps. Their `if` and
     `working-directory` are part of the step. So these jobs run no
     third-party action, no `curl | sh`, no `GITHUB_ENV` write and nothing
     from the bundle;
   - **P7:** no `continue-on-error`, job `container`, `services`,
     `concurrency`, `defaults` or `env` (the bake jobs' `BAKE_TARGET`,
     `PLATFORM`, `VERSION` and `BAKE_SET` aside), no workflow `env`, and
     `release`, `attest` and `attest-assets` run no repository code (no
     checkout, local action, `shell:`, code path or runtime; step env only
     `GH_TOKEN`, `TAG`, `VERSION`, `BASE`, `INDEX_DIGESTS`; design-system's
     rule);
   - **P8:** `on:` is only `workflow_dispatch` with `dry_run` (boolean,
     default `true`) and `version` (string, default `""`); the
     workflow-level `concurrency` is exactly `{group: release,
     cancel-in-progress: false}` (it serialises the runs that move
     `latest`); no `${{ }}` in a `run:` text; every `VERSION` env is
     `${{ needs.version.outputs.version }}`; `SOURCE_DATE_EPOCH` is
     required before the check step in `build`, `push` and
     `push-rehearsal`; a command that runs syft (the command word `syft`,
     or a `go run` of a package under `anchore/syft`) is only `go run
     github.com/anchore/syft/cmd/syft@v1.57.1 …` with
     `SYFT_CHECK_FOR_APP_UPDATE: "false"`;
   - **Everywhere in `release.yml`:** every `env` is a literal mapping (an
     `env: ${{ fromJSON(…) }}` would set any variable, `BASH_ENV`
     included, past the rules above); `actions/setup-go` has `cache:
     false`, so no job restores a Go module or build cache that another
     job on `main` wrote (#71 review B: such a cache runs its code inside
     `check-image-pins`, after `docker login`); `-verify-pushed`,
     `-publish-index`, `-move-latest`, `docker login` and
     `docker/login-action` appear only in the exact jobs. A mode counts in
     any spelling: its name anywhere in the run text once quotes and
     backslashes are gone (`-move-latest=true`, `--publish-index`, inside a
     `bash -c '…'` text), and `docker login` wherever its words stand in a
     command, an `sh -c` text included (#71 delta reviews A N1, B D2).
     Action names are compared without case (`Actions/Setup-Go@…` is
     `actions/setup-go`); `actions/cache` (and its `restore` and `save`
     actions), a `docker://` step and any `anchore/` action are reported in
     every job; a container run (`docker`, `podman` or `nerdctl` `run`,
     `create`, `container run`) is reported unless the step is exactly the
     build row's package-list line of the verified image; and every
     `docker/setup-buildx-action` has exactly CI's mirror and the pinned
     BuildKit image (A N2, N3; B D1).

   With the cache off, the tool's modules come fresh from the module proxy
   and are checked against `go.sum`; nothing earlier in an exact job runs
   code that could change them, so no `go mod verify` line is needed.

   In other workflows a `release-` cache scope in `BAKE_SET` is reported.
   Its tests are `TestReleaseWorkflow` (the repository's own `release.yml`
   is clean), `TestReleaseSurface` (the `fail-27-*` cases, each one change
   to the repository's `release.yml` in the tree
   `testdata/repos/pass-27-release`), `TestReleaseBuildMode` and
   `TestBuildRefusesPushedTar`. `make image-pins` checks the real
   `release.yml` in the repository.

**The release modes** run in `release.yml`'s write-token jobs, as the
fixed lines above, and take no argument and no tag name:
- `-verify-pushed` (`push`, `push-rehearsal`): `pushed.tar` is opened only
  as a regular file (Lstat, `O_NOFOLLOW`, fstat); every blob has its
  digest; `index.json` names the push step's `containerimage.digest`; that
  index holds one `linux/<arch>` image manifest and only attestations of
  it; its config is the tested config, the build row's
  `containerimage.config.digest` (`$RUNNER_TEMP/tested/metadata.json`;
  `-verify-built` requires it and `-save` holds exactly it). It writes
  `$RUNNER_TEMP/digest/<target>-<arch>.json`.
- `-publish-index` (`index`): checks every row's index and config in
  GHCR, then creates `<image>:X.Y.Z` with the version annotation; an
  existing `X.Y.Z` of the same content is a no-op and any other is never
  overwritten. It puts out `digests` (image to index digest).
- `-move-latest` (`latest`): first `git ls-remote --tags` of the constant
  `https://github.com/keepia/mail` (an empty temp directory, no git config,
  no inherited `GIT_*`, a 2-minute timeout): the highest `vX.Y.Z`
  (numeric; an annotated tag through its `^{}` line) must be `v$VERSION`
  on `GITHUB_SHA`. Then `X.Y.Z` must be the index job's digest, and
  `latest` moves only forward (its annotation and both configs' version
  label, all equal), with a check afterwards.

Every mode checks all images before it creates anything.

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
- Known limits of following what a step runs (#51):
  - a command given as literal words to a function that runs its
    arguments (`retry make publish` with `retry() { "$@"; }`): the words
    are read only as words of the text;
  - a function is known only in the text that defines it and its inline
    commands (`eval`, `sh -c`), not in a file that sources it
    (`. lib.sh; run "$@"`);
  - a shell that reads its program from stdin (`bash <<< "$*"`,
    `bash <&3`) is not read;
  - `xargs` and other words on PATH that run their arguments as a
    command (`xargs make publish`, `stdbuf`) hide those arguments;
  - a copy of the arguments made at the top level and used inside a
    function that is called with no arguments
    (`args=("$@"); run() { main "${args[@]}"; }; run`) is not followed;
  - reading `make` takes in the whole Makefile, which over-reports.

  In `release.yml`'s jobs with `packages: write` these limits do not apply:
  rule 7 resolves nothing there and allows only its fixed lines.
- Rule 7 checks `release.yml` on pull requests. A `workflow_dispatch` on a
  branch runs that branch's `release.yml`, which the branch can change; that
  residual risk is for review (#27, N10).
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

## Releases

[`.github/workflows/release.yml`](../../.github/workflows/release.yml)
publishes a release from `main`, started by hand; the runbook is in
[process.md, "Releases"](process.md#releases). The default is a dry run.

| Job | Runs in | Does |
|---|---|---|
| `version` | both | started on main; the pull requests since the last release, the version (`scripts/version-policy.sh LAST INPUT < prs.tsv`); the tag and release do not exist yet; the images and their tags |
| `build` | both | each image × amd64/arm64, cold: CI's build row (check, bake, verify, image tests, the saved and checked tar), `packages.txt`, syft v1.57.1 on the tar, `tools/release-sources row`; writes the release cache (`mode=max`) |
| `push-rehearsal` | dry run | `push` without the login and with `push=false` |
| `push` | real run | rebuilds from the release cache and pushes by digest; `-verify-pushed`: the pushed config is the tested config |
| `index` | real run | `-publish-index`: `ghcr.io/keepia/mail[-<name>]:X.Y.Z` with both platforms |
| `bundle` | both | `tools/release-sources release` (10 SBOMs, `sources.json`, `SOURCES.md`), the bundle, the notes head `notes.md`, and `SHA256SUMS`, which names exactly the other files; a dry run pins the placeholder digest `sha256:0…0`, a real run asserts that none is left |
| `attest` | real run | provenance of each image index, the SBOM of each platform manifest (`actions/attest`, GitHub's attestation API) |
| `attest-assets` | real run | provenance of every release asset |
| `release` | real run | refuses if any release of the tag exists (a draft too); the tag `vX.Y.Z` on the built commit and the GitHub release with every file of `dist` as an asset, so `sha256sum -c SHA256SUMS` passes on the downloads; removes its own tag and draft after a failure |
| `latest` | real run | `-move-latest`: `latest` to `X.Y.Z`, last and forward only |

**Tags.** `X.Y.Z` never changes. `latest` is the only tag that moves: it
follows every release, and **before 1.0 it follows every 0.x release, so
it can include breaking changes**. Pin `X.Y.Z` or a digest; the bundle
always pins every image by digest. No other tag exists.

**Verify** an image's provenance and a platform image's SBOM:

```sh
gh attestation verify oci://ghcr.io/keepia/mail-postfix:0.1.0 --owner keepia
gh attestation verify oci://ghcr.io/keepia/mail-postfix@<platform digest> --owner keepia \
  --predicate-type https://spdx.dev/Document/v2.3
```

**Labels.** Each own image carries its own `org.opencontainers.image.licenses`
(`docker-bake.hcl`; `tools/release-sources` fails on a target without
one) and `io.github.keepia.sources`, the URL of the release's
`SOURCES.md`.

**Pinned by hand.** The actions of `release.yml` are pinned in the tool too
(`actionPins` in `tools/check-image-pins/release.go`): a Dependabot pull
request that bumps an action there fails `make image-pins` until the same
pull request bumps `actionPins` (one line per action). The BuildKit image
of every builder (`driver-opts: image=moby/buildkit:vX.Y.Z@sha256:…` in
`ci.yml` and `release.yml`, `buildkitImage` in the tool) is not seen by
Dependabot: bump the three together by hand, to the release that
`moby/buildkit:buildx-stable-1` names.

**The release cache.** `build` writes `release-<image>-<arch>` scopes with
`mode=max` to the 10 GB Actions cache; `push` and `push-rehearsal` read
them. SOGo's build stage is the largest. #27 part 4b measured SOGo's
whole build in CI's builder (`docker buildx du` after the build, the
records a `mode=max` export holds, uncompressed): **1.86 GB on amd64 and
1.88 GB on arm64**, against a 302 MB (amd64) and 333 MB (arm64) final
image. The cache stores the layers compressed, so the two `release-sogo-*`
entries take less than about 3.7 GB of the 10 GB, but more than any other
image. When the cache is full, GitHub evicts the least recently used
entries, CI's first; that costs CI cache hits only. An evicted `release-`
entry between `build` and `push` makes the push row's rebuild differ, and
`-verify-pushed` stops the release (process.md, "Releases").

**The containerd image store.** `-verify-built` needs the build
metadata's `containerimage.config.digest` (the tested config the push is
compared with). A `--load` into a Docker daemon with the containerd image
store exports in OCI format, and that metadata has no config digest
(measured on Docker 29.9.2 in #71). The hosted runners use Docker 28 with
overlay2 today. If they move to the containerd store, `-verify-built`
fails closed in CI's `docker-build` and in the release's `build` rows,
and nothing is released until the check is reworked.

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
- A Dependabot bump of an action that `release.yml` uses needs the same
  bump of `actionPins` in `tools/check-image-pins/release.go`, in the same
  pull request, and the BuildKit image is bumped by hand
  ([Releases](#releases), "Pinned by hand").

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
