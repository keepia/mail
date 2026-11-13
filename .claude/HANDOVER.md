# Handover

Current state only. At session end replace these sections; never append. History lives in PRs, issues and git.

## Last release
- None yet. `.github/workflows/release.yml` came with #27 part 4b; its first dry run on `main` (test 17) follows the merge. Runbook: `docs/development/process.md`, "Releases".

## Open PRs
- Runbook skeleton for the mailcow migration (#28, part 1 of #13), docs only.
- Images part 1 (#24, part 1 of #5): Keepia, Postfix and Unbound images, `docker-build`/`docker` jobs, `tools/check-image-pins`, reload watcher. olefy moved to #44.

## Open tickets
- **0.1.0 (Foundation):**
  - #3 prototype: Dovecot 2.4 proxy routes users to two mail stores (`ready`);
  - #4 prototype: Dovecot 2.4 reads mail encrypted by mailcow's `mail_crypt` (`ready`);
  - #7 Keepia brand, in keepia/design-system (`ready`);
  - #2 architecture plan (`docs`; defines the resource budget in `docs/development/architecture.md`);
  - #5 Docker images and release pipeline;
  - #6 Go skeleton: service, CLI, Postgres migrations, health endpoint.
- **Not in a milestone (MQ4 open):** #13 migration runbook and import command: mailcow to Keepia Mail (`ready`); parts #28 (runbook skeleton, in PR), #29–#32 (outlines, each built after its plan revision is approved). Open maintainer questions on #13: MQ1, MQ2, MQ4–MQ7.

## Active decisions
- **Operating model:** one shared instance run by the operator; customers are separated by groups.
- **Public, MIT licence.**
- **Brand** lives in keepia/design-system (#7, 2026-11-11).
- The reference installation moves from mailcow to Keepia Mail with 1.0.0 (#13). Its runbook is `docs/operations/mailcow-migration.md`, placeholders only: no real value of the installation in the repository or on GitHub; reviewers of every #13 pull request run the plan's placeholder check.
- **Coordinator autonomy** (maintainer, 2026-11-11): as in `CLAUDE.md`.
- **Merge mechanics:** squash merge pinned to the reviewed head SHA (`expectedHeadSha`); a branch behind `main` is refused for required checks, so bring `main` in first.
- **CI jobs not yet in the ruleset:** `test`, `lint`, `vulncheck` (#6), `docker` (#5 part 1) and `compose` (#5 part 3, #26) count as required for merges until the ruleset lists them.
- **Compose template:** `docker-compose.yml` runs all roles on one server (14 containers plus the one-shot `edge-addresses`, `.env.example`, `deploy/`); the `compose` job loads the verified `docker-build` tars, runs them by image ID (`KEEPIA_*_IMAGE`) and runs `scripts/compose-test.sh` and `./km migrate`. Named volumes: `postgres-data`, `valkey-data`, `postfix-spool`, `edge-vmail`, `store-mail`, `store-index`, `store-users`, `rspamd-data`, `sogo-spool`.
  - Needs Docker Engine 28+: the internal networks use the gateway mode `isolated`, so the host cannot reach their services (#61). Engine 27 refuses the networks; 26 and older run without the isolation, silently (architecture section 7 has the check, meaningful after the first start: no host address in the internal subnets; `edge-public` keeps its gateway address).
  - A wildcard `EDGE_IPV4`/`EDGE_IPV6` is refused on `up` (`edge-addresses`) and again by `edge-postfix`'s entrypoint on any other start (#61). After a refusal: fix `.env`, `docker compose rm -f edge-postfix`, `up`.
  - Noted for later (Review B on PR #65): store-dovecot's `pids_limit: 256` before IMAP is exposed (N4); rule 4 does not read service keys such as `pull_policy: always`, which a plain `up` without `--pull never` would honour (N5).
  - **Valkey's healthcheck** probes loopback, the only address protected mode serves without a password. When its first client brings the password (0.2.0), move the probe to the private address with AUTH (#61, Review A N3 on #60).
  - **SOGo logs about 43k lines a day** in 0.1.0: it starts without a database route (the gate comes with 0.5.0) and each health probe logs about 30 lines. Only journald's retention (30 days) bounds them; check the host's journald size limits on a small disk (#61, Review A N4 on #60).
- **Images:** pins, privileges, healthcheck rules and the check's threat model in `.claude/rules/docker.md`; images are built only through `check-image-pins -bake-local` (`make images`) and CI's checked `docker/bake-action` step; `scripts/ci-docker-mirror.sh`, `ci-pull-images.sh` and `check-go-toolchain*.sh` stay byte-identical with mail-archive.
- **Releases** (#27): `release.yml` from `main` by hand, dry run first. `v0.1.0` is pre-approved (6845990778): the coordinator starts it after a green dry run on `main`, on the same commit, with every image built and the sums and SBOMs complete; if anything differs, it stops and reports. Every later real release needs the maintainer's OK. Tags `X.Y.Z` (immutable) and `latest` (moves forward only; before 1.0 it can include breaking changes); the bundle pins by digest. Rule 7 of `tools/check-image-pins` holds `release.yml` to its exact shape: a Dependabot bump of an action it uses needs the same bump of `actionPins` in `tools/check-image-pins/release.go`, and the BuildKit image (`moby/buildkit:v0.34.2@sha256:c5f8862f…`, in `ci.yml`, `release.yml` and the tool's `buildkitImage`) is bumped by hand. The coordinator never deletes package versions.
- **Workflow changes:** a change to `.github/workflows/`, `tools/check-action-pins/`, the Makefile's `workflows`/`workflows-test` targets, or the `go.yaml.in/yaml/v3` line in `go.mod` gets `second-review`.
- **Resource budget:** plans state memory and CPU per role and for all roles on one server, against `docs/development/architecture.md` once #2 is merged.

## Maintainer actions
- Add `test`, `lint`, `vulncheck` to the `main` ruleset (#6), after their first green run; `docker` and `compose` (#5) after their first green run on `main`.
- Delete the remote branch `proof/secret-scan`.
- The OK for each real release after `v0.1.0` (pre-approved, 6845990778), after a green dry run (`process.md`, "Releases").
- After the first release: make the five GHCR packages (`mail`, `mail-postfix`, `mail-unbound`, `mail-olefy`, `mail-sogo`) public and link them to keepia/mail.
- After a failed push row: delete the untested and orphaned package versions the coordinator names.
