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
| `KEEPIA_KEK_FILE` | `/var/lib/keepia/kek/kek` | `serve`: the key-encryption key ([Control secrets](#control-secrets)); its `kek.new` lives next to it |

Commands: `serve` (migrate, create or load the [control
secrets](#control-secrets), then answer `GET /healthz`), `migrate`,
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
is a no-op; `00003_control_secrets.sql` holds the control secrets (#96).
`00002` is reserved for the data model (#95): goose orders by number and
accepts the gap, but refuses a lower version that arrives after a higher
one is applied, so the pull request that merges second renumbers its
migration above main's highest (#95, cross-plan decision CD-C1).

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

## Control secrets

`serve` creates the control secrets at its first start and loads them at
every later one, after the migrations and before it listens (#96 part 1;
`internal/secrets`, `internal/pki`):

- **The key-encryption key (KEK)** is the file `KEEPIA_KEK_FILE`
  (`/var/lib/keepia/kek/kek`) on the named volume `keepia-kek`, which only
  `keepia` mounts. The file is one line, `keepia-kek-v1 <base64url of 32
  random bytes>`, mode 0400, owner 65532, in a 0700 directory that the
  image ships with that owner and mode (Docker copies them into a new,
  empty volume). It is never in the database or in `.env`. `serve` opens
  it with `O_NOFOLLOW|O_NONBLOCK` and checks type, mode and owner on the
  opened file: a link, a FIFO, a directory, group or other permission
  bits, another owner than the process, or any other content is refused,
  and the error never quotes the file.
- **The secrets** are six rows of `control_secrets` (the keys of the four
  anchors `store-client`, `groupware-client`, `agent` and `service`, the
  store master password, and the global mail_crypt key pair) and one
  `secret_keyring` row with the KEK id and a random deployment id. Each
  value is sealed with AES-256-GCM (random nonce) under a key derived from
  the KEK with HKDF-SHA256; the additional data binds it to its name,
  version, KEK id and public part, so a row copied to another name or
  paired with another certificate does not open. The database holds only
  ciphertext: a dump without the KEK reveals no secret.
- **Losing the KEK loses all mail** (the mail_crypt key is sealed under it)
  and every certificate, and it is not in a database dump. Back up the
  volume `keepia-kek` apart from the server; `secrets export` follows with
  #96 part 2. At the first start `serve` logs, at WARN, `control secrets
  created: the key-encryption key is /var/lib/keepia/kek/kek on the volume
  keepia-kek. …`; while the secrets have never been exported, every later
  start logs the same text as `control secrets never exported: …`.
- **The first start** writes `kek.new` (`O_EXCL`, fsync), commits the
  keyring and the six secrets in one transaction, then links `kek.new` to
  `kek` (never over an existing file), removes `kek.new` and syncs the
  directory. It holds the bootstrap lock, a session-level advisory lock
  (`internal/store/locks.go`, class 9601, key 0) on a connection of its
  own, from before it reads anything until the link is synced. Commands
  that read the secrets take the same lock shared, for at most 30 s.

**Locked.** `serve` never generates over existing secrets. When the files
and the database do not fit together, it logs one ERROR `control secrets
locked: …`, keeps running and answers `/healthz` with 503 `secrets
unavailable` (so `keepia` shows unhealthy, but `docker compose exec` still
works). Fix the cause with `keepia` stopped, then start it again. There is
no shell in the image: to look at or change the volume, use a one-shot
container of an image the template already pulled, for example

```sh
docker compose stop keepia
docker run --rm --pull never --network none --user 65532:65532 \
  -v keepia-mail_keepia-kek:/kek --entrypoint ls <the memcached image of docker-compose.yml> -la /kek
docker compose up -d --no-build --pull never keepia
```

| State | Message starts with | Recovery |
|---|---|---|
| No `kek`, secrets in the database | `KEK missing` | Restore `kek` from a backup of the volume `keepia-kek` (or, from #96 part 2 on, `./km secrets restore`), or restore the database that belongs to the lost KEK. |
| No `kek`, a `kek.new` that is not the database's KEK (or does not load) | `stray kek.new` | It is kept. Restore the right `kek`; if `kek.new` is not a KEK you need (a partial write), remove it with `--entrypoint rm` as above. |
| `kek` present, no secrets in the database | `KEK without secrets` | Restore the database that matches this KEK; for a fresh install, remove the volume `keepia-kek` (`docker volume rm keepia-mail_keepia-kek`). |
| `kek` of another deployment (ids differ) | `wrong KEK`, naming both ids | Restore the `kek` whose id the database names, or the database that belongs to this `kek`. |
| `kek` matches, `kek.new` differs | `stray kek.new` | It is kept: remove it once you know it is not needed. |
| `kek` refused (mode, owner, link, format) | `KEK file refused` | Fix the file: mode 0400, owner 65532, one KEK line; or restore it from a backup. |
| A sealed row does not open, or a secret is missing | `sealed secret does not open` or `control secrets incomplete` | The database was changed or mixed with another one: restore it from a backup that matches the KEK. |

A `kek.new` is removed only when the keyring is empty and there is no
`kek` (an interrupted first start, which then starts over), or when it is
identical to `kek`. A `kek.new` that matches the database while `kek` is
missing (a crash between the commit and the link) is linked into place at
the next start; a command that meets this state reports `bootstrap in
progress`.

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
  0.2.0), it first watches the directory, reads `generation` and logs
  `watching … (generation at start: N|none)`, and only then starts the
  service. A `generation` file written there (write, then rename) runs the
  image's reload command (`postfix reload`, `unbound-control reload`); the
  first reload waits for the image's ready command
  (`keepia-reload-ready`: the Postfix master handles SIGHUP;
  `unbound-control status`). The container exits when the service or the
  watcher stops, so a dead watcher cannot silently drop reloads
  (architecture section 5). Without the directory the service runs alone.
  The contract for the agent (#45; the full text is the watcher's header):
  - write every config file first, then `generation` last, by rename;
  - `generation` holds 1 to 19 decimal digits with no leading zero
    (except `0`) and at most one trailing newline, in a regular file that
    the service user can read (root for Postfix, uid 10053 for Unbound);
    a symlink, a FIFO, other content or an unreadable file is refused and
    logged without its content, with no reload;
  - values are never reused on a volume: the agent writes
    `max(file + 1, control generation)`. The watcher reloads on any valid
    value that differs from the one it applied and ignores an equal one;
  - a failed reload is retried (1 s, doubling to 30 s) for as long as the
    container runs; several writes may collapse into one reload;
  - there is no acknowledgement: only the log shows
    `reload of generation N done`, so for Postfix and Unbound the agent can
    report only the generation it wrote.
- **Image tests** ([`scripts/image-test.sh`](../../scripts/image-test.sh)):
  the smoke command; user, capabilities and `NoNewPrivs`; the healthcheck
  green, then red with every process of the container stopped (and, for
  Postfix, red with Debian's `chroot = y`, while `postfix status` still says
  running); the reload watcher (#45, T1 to T12: a generation written
  before or during start-up, an equal value ignored and a lower one
  reloaded, a symlink, a FIFO and bad content refused without a leak or a
  hang, a failed reload retried, the ready gate only until its first
  success, a config broken from the start still reloaded, a stop during the
  set-up, no event pipe in the service, a watch that cannot be set up;
  killing `inotifywait` stops the container with status 1, also during a
  pending retry); and a clean `docker stop`. Every wait reads a Docker
  event or a log line, bounded by a timeout. For a local run,
  `IMAGE_TEST_CASES` limits the cases (`make image-test IMAGE=postfix
  IMAGE_TEST_CASES="t1 t2"`; the names are in the script's header).

### The Compose template

[`docker-compose.yml`](../../docker-compose.yml) holds every role, one
profile each (architecture section 7); with
`COMPOSE_PROFILES=control,edge,store,filter,groupware` it is the template
"all roles on one server": 14 containers, plus the one-shot
`edge-addresses`, which exits once it has checked the edge addresses. It
needs Docker Engine 28 or later (the gateway mode `isolated`): Engine 27
refuses to create the networks, and 26 or older creates them without the
isolation, silently. [Architecture section 7](architecture.md#7-docker)
has the check: the host must have no address in the internal subnets
(`edge-public`, which is not internal, keeps its gateway address on the
host). Its version line works at any time; the other two lines are
meaningful only while the template is running (its networks exist).
Before the first start and after `docker compose down` its last line
prints nothing on any Engine, which is no all-clear.

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
  creates no anonymous volume. The ten are `keepia-kek` (the
  key-encryption key, mounted only into `keepia`; see [Control
  secrets](#control-secrets)), `postgres-data`,
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
network reaches them, the fixed addresses and the only published port,
and the subnet line of
[architecture section 7](architecture.md#7-docker), read from there
(accepted only in its one fixed form, otherwise a failure without running
it) and run with no active profile, lists exactly the internal subnets
(test 9); capabilities, `no-new-privileges`, `pids_limit` and uids, and
`edge-postfix`'s entrypoint and command equal to its image's with the
edge address check after `tini --` (test 10); a message over LMTP into
the named volume `store-mail`, an empty `edge-vmail` and no anonymous
volume (test 11); the edge's `451 4.3.0` and `NO [UNAVAILABLE]` (test
12); and the edge SNAT and DNAT rules (test 13). At its end it stops the
running `edge-postfix`, which must exit 0 and not be OOM-killed (test
14b); the other services keep running for test 7. It runs every test and
names each failure; every helper run is bounded by a timeout. It still
needs sudo for the NAT rules (test 13) and, in CI, to put the edge
addresses on loopback.

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

**R1, no network in RUN.** Every row also checks its Dockerfile: every
RUN of an image Dockerfile carries `--network=none`, except two forms.
One is the `keepia-apt-install` form:
`RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install [--mount=type=secret,id=ca,…] sh /tmp/keepia-apt-install <package>...`.
The other is the root Dockerfile's single `go mod download` RUN in its Go
build stage, whose modules `go.sum` pins and `go mod verify` checks; the
`go build` after it has `--network=none` as well (#66). That RUN's text is
the constant `goModDownload` in `tools/release-sources/main.go`, so an
edit to the RUN updates the constant in the same PR: the test of the real
Dockerfile in `go test ./tools/release-sources/` fails otherwise.

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
`fixture_test.go`. They are regenerated the same way (build,
`-verify-built -save`, syft, the filter) on a syft bump, and also when one
of olefy's pinned wheels or the SOGo pin moves, because the packages,
versions and paths they hold change with it (#51).

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
   `BUILDKIT_SYNTAX`; a URL context, `extends` and `include` are reported.
   So is a service's `pull_policy`, whatever its value (#66 item 9b): the
   template is started only with `--pull never`, but a plain `up` without
   it would honour the key, and `always` would pull an own image by tag
   over the verified one;
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
     - **Makefile rules: a fast filter, not a proof** (see "Known limits
       of the Makefile rules" under the threat model). In a Makefile
       (`Makefile`, `makefile` or `GNUmakefile` in any directory; the
       check matches these names in any letter case) or `*.mk` file the
       check reports `buildx` and `BUILDX_` anywhere
       (after quotes are removed) and any other build command; setting
       or exporting `PATH` or `HOME`, and naming `DOCKER_CONFIG`,
       `DOCKER_HOST` or `DOCKER_CONTEXT` (local mode passes these to
       docker, and make passes its own value of an environment variable
       to a recipe even without `export`); setting `SHELL` or
       `.SHELLFLAGS`; setting or exporting `GOFLAGS`, `GOENV` or
       `GOWORK`; an include of anything but a relative path of letters,
       digits, `.`, `_`, `-` and `/` ending in `.mk`, not under `../`
       and not in a skipped directory (an allowlist on the line as
       written, before quote removal, not a model of how make reads the
       path: see "Known limits of the Makefile rules" below; the check
       does not verify that the file exists or that the walk read it;
       generated includes are a known limit); and a variable name it
       sees as computed (`export
       PA$(E)TH`, or a name built by a function call such as
       `$(eval $(firstword GO) := …)`).

       `GO` may be set only on a line that is exactly `GO ?= go`,
       `GO := go`, `GO = go`, `override GO := go` or `export GO := go`
       (`make images` runs `$(GO) run ./tools/check-image-pins`; blanks
       around the operator may vary; no comment; the line before may not
       end in `\`). For `GO` the check reads the raw file text, before
       any quoting, comment or continuation handling, and does not model
       make's syntax (#51; three review rounds found holes in a parser):
       any other text that assigns or defines `GO`, that is `GO` before
       `=`, `:=`, `::=`, `:::=`, `?=`, `+=` or `!=` (also across a `\`
       continuation) or `define GO`, is reported wherever it stands, in
       a recipe, a `$(eval …)`, a target-specific variable, `MAKEFLAGS`,
       a comment, or an allowlisted line with a comment (under
       `.RECIPEPREFIX` such a line is a recipe, and make expands
       `GO = go # $(eval GO := ./evil)`). It over-reports on purpose: a
       recipe's `GO=go $(MAKE) x` and a comment that quotes `GO = go` are
       reported too, and are written differently.
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
   GHCR credentials (#71 review B, N6). Outside `release.yml` that step
   has exactly CI's inputs, the pinned image and the mirror (no other
   `driver-opts` entry such as `network=host`, no other
   `buildkitd-config-inline`, no explicit `driver`; #66 D3); rule 7 holds
   `release.yml`'s own. And in every workflow a job builds with the
   builder that step started (#66 D2): a step that runs `docker buildx
   create` or `use` (also `docker builder …`, buildx's alias, and the
   `docker-buildx` plugin binary) or `docker context create`, `import` or
   `use`, in its own text or `github-script`, and in a job that builds
   with bake also in a script, make target or local action it runs, is
   reported; so is `BUILDX_BUILDER`, `DOCKER_CONTEXT` or `DOCKER_HOST` in
   the workflow, job or step `env`, and outside `release.yml` an `env`
   that is not a literal mapping;
7. **the release surface** (#27,
   [`release.go`](../../tools/check-image-pins/release.go)): `release.yml`
   has exactly the planned shape, so the one workflow that can push cannot
   grow a second push path. The policy is data in the tool:
   - **P2, P6:** exactly the eleven jobs `version`, `build`,
     `push-rehearsal`, `push`, `push-arm64`, `index`, `bundle`, `attest`,
     `attest-assets`, `release` and `latest`, each with exactly its
     permissions, `needs` and `if` (top-level `permissions: {}`;
     `packages: write` only in `push`, `push-arm64`, `index` and
     `latest`, none of which runs in a dry run), and no job `uses:`;
   - **Principle A, the conditions (#77):** rule 7 reads every job's
     `needs` and `if` from the workflow and evaluates them under GitHub's
     rules: an `if` without a status function gets an implicit
     `success()`, and at job level `success()` is true only if every
     ancestor (the transitive `needs`) succeeded, so a skipped ancestor
     makes it false. In a real run `push-rehearsal` is always skipped, so
     on `1f29fb1` the bare `${{ !inputs.dry_run }}` of `attest`,
     `attest-assets`, `release` and `latest` skipped them in the real run
     43420238830, which still concluded "success". So:
     - **form:** a job with an ancestor that runs in one mode only has
       exactly the explicit condition `${{ !cancelled() && <mode> &&
       needs.<j>.result == 'success' && … }}`, one term per direct need
       in the policy's `needs` order (`bundle`, which runs in both
       modes, has the dry and the real needs each behind its mode term).
       The policy generates these conditions (`releaseCondFor`) and
       `TestReleasePolicyConds` pins them literally. `version` and
       `build` have no `if`; `push` and `push-rehearsal` keep the bare
       mode term;
     - **grammar:** exactly one `${{ }}` around the whole value (or
       none), with no whitespace around it, Unicode whitespace and a
       block scalar's (`if: |`) trailing newline included: GitHub reads
       such a value as a string, which is true, so it is refused, never
       trimmed, and the simulation counts it as always true;
       `!`, `&&`, `||`, parentheses, `inputs.dry_run`,
       `needs.<direct need>.result == 'success'`, `success()`,
       `failure()`, `cancelled()` and `always()`; anything else
       (`github.*`, `contains()`, `!=`, a reversed comparison, a need that
       is not direct, `!needs.<j>.result`) is a finding, never accepted;
     - **job sets:** every job is simulated in both modes, every job that
       runs passing. A real run runs exactly `version`, `build`, `push`,
       `push-arm64`, `index`, `bundle`, `attest`, `attest-assets`,
       `release` and `latest`; a dry run exactly `version`, `build`,
       `push-rehearsal` and `bundle`;
     - **failure injection:** in each mode, each job that runs is made to
       fail once; exactly the planned set minus its descendants must
       start (a missing result term, or `always()`, would run a job
       after a failed need);
     - a need that names no job and a cycle are findings.

     The model reproduces the two measured runs on `1f29fb1`
     (`TestReleaseModelMeasuredRuns`). It proves that the jobs start, not
     that their steps pass: `attest`, `attest-assets`, `release` and
     `latest` ran for the first time in the first real release;
   - **P3, P4, P5, P9:** in `push`, `push-arm64`, `push-rehearsal`,
     `index` and `latest`, every step is exactly the policy's step at
     its position (`push-arm64` has `push`'s steps): an
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
     `push-rehearsal` is `push` without the login, with the local registry
     service and a host-network builder (#75): it pushes by digest too,
     to `localhost:5000/keepia/…` on the runner, so BuildKit's push path
     runs in every dry run. Its setup-buildx step adds `network=host` to
     `driver-opts`; every other job keeps CI's bridge builder.
     The bake jobs' `BAKE_SET` holds exactly the release cache line, and in
     the push jobs the target's tags (the bare repository:
     `ghcr.io/keepia/mail[-<name>]` in `push`,
     `localhost:5000/keepia/mail[-<name>]` in `push-rehearsal`), the two
     outputs (`type=image,push-by-digest=true,name-canonical=true,push=true`
     and `type=oci,dest=pushed.tar`) and `attest=type=provenance,mode=max`;
     build mode checks what they resolve to (the build job's tags
     `ghcr.io/keepia/mail[-<name>]:VERSION`, a push job's tags one of the
     two bare repositories, `push=true` and `push-by-digest=true`), and
     `VERSION` as X.Y.Z, and refuses a `pushed.tar` that exists in any
     form. The tags are bare because BuildKit refuses push-by-digest of a
     tagged name (`can't push tagged ref … by digest`, run 43401448419).
     A bare name is safe only with `push-by-digest=true`: without it,
     BuildKit pushes the name as `:latest`. A script allowlisted for these
     jobs (none) may have no forwarding function;
   - **P9, principle B (#77): no two rows push to the same package at
     once.** `push` runs the build job's images on `amd64` only,
     `push-arm64` the same images on `arm64` only and needs `push`, so
     every arm64 row starts after every amd64 row has created its
     package; `push-rehearsal` runs the build job's whole strategy (each
     row pushes to its own runner's registry). In run 43420238830 two
     rows of `mail-unbound` pushed while GHCR created the package, and
     the arm64 row was refused with `denied`;
   - **`attest`, `attest-assets` and `release` have exact steps too**
     (#27 part 4b, #71 review B N2), the same way: the `dist` and `digest-*`
     artifacts, `sha256sum -c SHA256SUMS` in `dist`, `attest`'s subjects
     step (the index digests from `index`, the platform manifests from the
     push rows' digest files, each checked as `sha256:<64 hex>`), one
     `actions/attest` step per subject (the provenance of each image's
     index, the SBOM of each platform manifest, every release asset), and
     `release`'s tag, release and cleanup steps. The tag and cleanup
     steps list the releases through the REST API, which shows drafts to
     the job's `contents: write` token: the tag step refuses on any
     release of the tag and on a failed call; the cleanup deletes nothing
     on a failed call or a published release, else each draft of the tag
     by its id, then the tag (#66 D1: `gh release view` looked drafts up
     through GraphQL and failed open; `TestReleaseTagLines` runs both
     lines against a stub `gh`). Their `if` and
     `working-directory` are part of the step. So these jobs run no
     third-party action, no `curl | sh`, no `GITHUB_ENV` write and nothing
     from the bundle;
   - **P7:** no `continue-on-error`, job `container`, `services` (except
     `push-rehearsal`'s, exactly the pinned `registry` image on
     `127.0.0.1:5000` with no env, options, credentials, volumes or other
     port; the maintainer's OK 6850628924), `concurrency`, `defaults` or
     `env` (the bake jobs' `BAKE_TARGET`,
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
     required before the check step in `build`, `push`, `push-arm64` and
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
     BuildKit image (A N2, N3; B D1), plus `network=host` in
     `push-rehearsal` only (rule 6 holds every other workflow to exactly
     CI's inputs, #66 D3).

   With the cache off, the tool's modules come fresh from the module proxy
   and are checked against `go.sum`; nothing earlier in an exact job runs
   code that could change them, so no `go mod verify` line is needed.

   In other workflows a `release-` cache scope in `BAKE_SET` is reported,
   and so is a `tags`, `output` or `attest` line.
   Its tests are `TestReleaseWorkflow` (the repository's own `release.yml`
   is clean), `TestReleaseSurface` (the `fail-27-*`, `fail-75-*` and
   `fail-77-*` cases, each one change
   to the repository's `release.yml` in the tree
   `testdata/repos/pass-27-release`), `TestBuilderRules` (rule 6's
   `fail-66-d2-*` and `fail-66-d3-*` cases in the same tree, and no such
   finding on the repository's `ci.yml` and `release.yml`),
   `TestReleaseTagLines` (the tag and cleanup lines under `bash -eo
   pipefail` with a stub `gh` and the system `jq`; no network),
   `TestReleaseBuildMode`, `TestBuildRefusesPushedTar`, and principle
   A's unit tests in
   `release_graph_test.go` (the pinned conditions, the measured runs,
   GitHub's rules on small graphs, the grammar and its precedence).
   `make image-pins` checks the real `release.yml` in the repository.

**The release modes** run in `release.yml`'s write-token jobs, as the
fixed lines above, and take no argument and no tag name:
- `-verify-pushed` (`push`, `push-arm64`, `push-rehearsal`): `pushed.tar` is opened only
  as a regular file (Lstat, `O_NOFOLLOW`, fstat); every blob has its
  digest; `index.json` names the push step's `containerimage.digest`; that
  index holds one `linux/<arch>` image manifest and only attestations of
  it; its config is the tested config, the build row's
  `containerimage.config.digest` (`$RUNNER_TEMP/tested/metadata.json`;
  `-verify-built` requires it and `-save` holds exactly it). The push
  step's metadata must name exactly `<R>/mail[-<name>]:latest` (buildx's
  name for the bare repository), with `R` `ghcr.io/keepia` or
  `localhost:5000/keepia`. Then, once the tar has passed, it reads the row
  back from that registry, the same check `-publish-index` runs per row:
  the index has its digest and the tar's bytes, holds the tar's
  `linux/<arch>` manifest, and its config is the tested config (anonymous
  on `localhost` in `push-rehearsal`, with the login in `push` and
  `push-arm64`). A failed
  read gets its own finding, `the registry read failed: …`, apart from a
  mismatch (`the registry holds other content than pushed.tar …`); the
  runbook treats the two differently (process.md, "Releases", step 5).
  The success line names the registry. It writes
  `$RUNNER_TEMP/digest/<target>-<arch>.json`, whose `repository` is where
  the row was pushed: a rehearsal's `localhost:5000/keepia/…` record is
  refused by `-publish-index` and by `attest`'s subjects step.
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
  step cannot reroute the tool's own build. Locally the Makefile rules
  filter `SHELL`, `GO` and the Go variables the tool is built with; they
  are not a proof (known limits below).
- Known limits of following what a step runs (#51). They apply in every
  workflow except `release.yml`'s jobs with exact steps (today: `ci.yml`,
  and `release.yml`'s `version`, `build` and `bundle`). There a limit can
  change which image a test runs or hide a build path, but not what is
  pushed: only the exact jobs hold `packages: write` (rules 6 and 7), the
  push jobs rebuild through bake, and `-verify-pushed` compares the pushed
  config with the build job's tested config. A hidden build is refused at
  verify-built (the local ID is not the bake digest) or never tested,
  because the test runs the verified ID; workflow edits get
  `second-review`. Reviewers look for these forms.

  Not followed (fail open):
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
  - a program that runs commands itself: `go run ./tools/<x>`,
    `npm run <script>`, a `shell: python` step with `subprocess`. The check
    follows `run` text, github-script, local actions and the scripts and
    make targets they name, nothing else (51-1);
  - a build or push written in another program (a Go composite literal
    such as `[]string{"build"}`, a Rust builder), and `oras push` or
    `regctl image copy`, which rule 7 refuses in the push jobs (51-2);
  - a copy of the arguments run by a function that is called with no
    arguments, whether the copy is made at the top level
    (`args=("$@"); run() { main "${args[@]}"; }; run`) or in another
    function (`parse_args() { CMD=("$@"); }; parse_args "$@"; run`)
    (51-8);
  - a `for c in "$@"` (or `for c;`) loop variable passed to a forwarding
    function (51-9);
  - `printf -v c '%s ' "$@"`, scalar copy chains (`b=$a`,
    `b="${a[*]}"`), `${a[0]}` after `mapfile`, and a top-level
    `cmd="$*"` used in a function called with `"$@"` (51-10);
  - a test by tag through a wrapper (a Makefile target or script) whose
    name does not contain `image-test` (51-11). Rules 6 and 7 do not
    cover this one; only review does. A test by tag after verify still
    tests the verified image unless something re-tags in between.

  Over-reports (fail closed):
  - reading `make` takes in the whole Makefile and its includes: every
    recipe counts, whichever target runs, and file names in comments are
    followed (51-5; no job that bakes runs `make` today);
  - `&&` inside `[[ … ]]` splits the test, so
    `[[ $out == a && $out == b ]] || fail` is reported as running `$out`
    (51-7);
  - the contents of `$(( ))` are read as commands, and data-only
    arguments to a forwarding function (`quietly ls "$HOME"`) are
    reported (51-12).

  In `release.yml`'s jobs with `packages: write` these limits do not apply:
  rule 7 resolves nothing there and allows only its fixed lines.
- Known limits of the Makefile rules (#51, PR #91; maintainer decision
  6865260080). check-image-pins does not prove that a Makefile is safe:
  its Makefile rules are a fast filter that fails closed on the forms
  they know. Not caught, among others (`TestMakefileKnownLimits` pins these):
  - a variable name computed with `$` plus a blank, a tab or a
    backslash-newline (`$ ` is the empty one-character variable):
    `G$ O := ./evil`, `PA$ TH := …`, `SHE$ LL := …`. They get past the
    `GO`, `PATH` and `SHELL` rules alike;
  - a generated or remade include: `include gen.mk` with a rule that
    makes `gen.mk` from a file no rule reads. Make remakes it and then
    reads it;
  - a name quoted for a sub-make in a recipe:
    `$(MAKE) images G''O=./evil`, `MAKEFLAGS=G''O=./evil $(MAKE) …`.

  Review owns Makefile changes: `Makefile`, `makefile`, `GNUmakefile`
  (in any directory) and `*.mk` are in the `paths:` of
  `.claude/rules/docker.md`, so every change to them gets
  `second-review`. No CI or release image build goes through make: they
  build only through `docker/bake-action` after `-build`, and
  `make images` runs only on developers' machines.
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
| `push-rehearsal` | dry run | `push` without the login: pushes by digest to its own `registry` service on `127.0.0.1:5000` (pinned, loopback only, host-network builder), so BuildKit's push path runs; nothing leaves the runner |
| `push` | real run | the amd64 rows: rebuilds from the release cache and pushes by digest under the bare repository `ghcr.io/keepia/mail[-<name>]` (no tag); `-verify-pushed`: the pushed config is the tested config, read back from GHCR |
| `push-arm64` | real run | `push` for the arm64 rows, after every amd64 row, so the two architectures of a package never push at once (#77) |
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

**The provenance subject names `@latest`.** The push rows push by digest
under the bare repository (BuildKit refuses push-by-digest of a tagged
name, #75), so BuildKit's own provenance attestation of each platform
image (`attest=type=provenance,mode=max`) names its subject `pkg:docker/ghcr.io/keepia/mail[-<name>]@latest?platform=linux%2F<arch>`:
BuildKit's name for a repository without a tag. It moves no tag (the
push writes none) and the subject's digest is the binding part; a reader
of an old release's provenance sees `latest` there, not `X.Y.Z`.

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
`moby/buildkit:buildx-stable-1` names. The same holds for
`push-rehearsal`'s registry service
(`mirror.gcr.io/library/registry:X.Y.Z@sha256:…` in `release.yml`,
`registryImage` in the tool): bump both together by hand.

**The release cache.** `build` writes `release-<image>-<arch>` scopes with
`mode=max` to the 10 GB Actions cache; `push`, `push-arm64` and
`push-rehearsal` read them. SOGo's build stage is the largest. #27 part 4b measured SOGo's
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
