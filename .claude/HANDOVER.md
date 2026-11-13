# Handover

Current state only. At session end replace these sections; never append. History lives in PRs, issues and git.

## Last release
- **v0.1.0** (2026-11-13), from `8c7647d`, run 43433927200: <https://github.com/keepia/mail/releases/tag/v0.1.0>. Five images in GHCR (`mail`, `mail-postfix`, `mail-unbound`, `mail-olefy`, `mail-sogo`), tags `0.1.0` and `latest`, public and pullable anonymously. The release page holds the bundle, ten SPDX SBOMs, `SOURCES.md`, `sources.json`, `notes.md` and `SHA256SUMS`; provenance and SBOM attestations exist. Not a working mail server.
- It took three fixes found only in real runs: SBOM python/npm attribution (#73), push by digest under the bare name with a rehearsal that really pushes (#75), and explicit job conditions with rule 7's mode simulation plus `push-arm64` after `push` (#77). Summary on #5.

## Open PRs
- #47 Dependabot: `go.yaml.in/yaml/v3` 3.0.5 → 3.0.6. Touches the `go.mod` line that needs `second-review`; not yet triaged.

## Open tickets
- **0.1.0:** #5 (images and release pipeline) closes with this handover; then the milestone closes.
- **0.2.0:** #66 low-priority image hardening notes (D1–D4).
- **0.4.0:** #52 documentation site.
- **No milestone:** #51 check-image-pins review notes (collected, incl. #73–#78 notes); #45 reload watcher follow-up; #13 mailcow migration with parts #29–#32 (another agent's work; open maintainer questions on #13).
- **Next per maintainer:** cleanup first (#51, #66), then the 0.2.0 plan.

## Active decisions
- **Operating model:** one shared instance run by the operator; customers are separated by groups.
- **Public, MIT licence.**
- **Brand** lives in keepia/design-system (#7, 2026-11-11).
- The reference installation moves from mailcow to Keepia Mail with 1.0.0 (#13). Its runbook is `docs/operations/mailcow-migration.md`, placeholders only: no real value of the installation in the repository or on GitHub; reviewers of every #13 pull request run the plan's placeholder check.
- **Coordinator autonomy** (maintainer, 2026-11-11): as in `CLAUDE.md`.
- **Merge mechanics:** squash merge pinned to the reviewed head SHA (`expectedHeadSha`); a branch behind `main` is refused for required checks, so bring `main` in first. Before the merge a PR comment names the reports read and checks every Done-when item.
- **Required checks** (ruleset on `main`): `secret-scan`, `links`, `workflows`, `test`, `lint`, `vulncheck`, `compose`, `docker`.
- **Compose template:** `docker-compose.yml` runs all roles on one server (14 containers plus the one-shot `edge-addresses`, `.env.example`, `deploy/`); the `compose` job loads the verified `docker-build` tars, runs them by image ID (`KEEPIA_*_IMAGE`) and runs `scripts/compose-test.sh` and `./km migrate`. Named volumes: `postgres-data`, `valkey-data`, `postfix-spool`, `edge-vmail`, `store-mail`, `store-index`, `store-users`, `rspamd-data`, `sogo-spool`.
  - Needs Docker Engine 28+: the internal networks use the gateway mode `isolated`, so the host cannot reach their services (#61). Engine 27 refuses the networks; 26 and older run without the isolation, silently (architecture section 7 has the check, meaningful after the first start: no host address in the internal subnets; `edge-public` keeps its gateway address).
  - A wildcard `EDGE_IPV4`/`EDGE_IPV6` is refused on `up` (`edge-addresses`) and again by `edge-postfix`'s entrypoint on any other start (#61). After a refusal: fix `.env`, `docker compose rm -f edge-postfix`, `up`.
  - Noted for later (Review B on PR #65): store-dovecot's `pids_limit: 256` before IMAP is exposed (N4); rule 4 does not read service keys such as `pull_policy: always`, which a plain `up` without `--pull never` would honour (N5).
  - **Valkey's healthcheck** probes loopback, the only address protected mode serves without a password. When its first client brings the password (0.2.0), move the probe to the private address with AUTH (#61, Review A N3 on #60).
  - **SOGo logs about 43k lines a day** in 0.1.0: it starts without a database route (the gate comes with 0.5.0) and each health probe logs about 30 lines. Only journald's retention (30 days) bounds them; check the host's journald size limits on a small disk (#61, Review A N4 on #60).
- **Images:** pins, privileges, healthcheck rules and the check's threat model in `.claude/rules/docker.md`; images are built only through `check-image-pins -bake-local` (`make images`) and CI's checked `docker/bake-action` step; `scripts/ci-docker-mirror.sh`, `ci-pull-images.sh` and `check-go-toolchain*.sh` stay byte-identical with mail-archive. ClamAV stays on 1.4 LTS (maintainer); a Dependabot ignore for ≥1.5 is item 10 of #66.
- **Releases:** `release.yml` from `main` by hand (`docs/development/process.md`, "Releases"). Dry run first; every real release after v0.1.0 needs the maintainer's OK via AskUserQuestion. After every run the coordinator checks the latest attempt's job list (`attempts/<n>/jobs?per_page=100`) against the exact set for its mode. Tags `X.Y.Z` (immutable) and `latest` (forward only; before 1.0 it can include breaking changes); the bundle pins by digest. Rule 7 of `tools/check-image-pins` holds `release.yml` to its exact shape and simulates both modes; a Dependabot bump of an action it uses needs the same bump of `actionPins` in `tools/check-image-pins/release.go`, and the BuildKit image (`moby/buildkit:v0.34.2@sha256:c5f8862f…`) and the rehearsal's `registry` image are bumped by hand. GPL parts on GHCR: references plus SBOM (`SOURCES.md`), no source bundle. The coordinator never deletes package versions.
- **Workflow changes:** a change to `.github/workflows/`, `tools/check-action-pins/`, the Makefile's `workflows`/`workflows-test` targets, or the `go.yaml.in/yaml/v3` line in `go.mod` gets `second-review`.
- **Resource budget:** plans state memory and CPU per role and for all roles on one server, against `docs/development/architecture.md`.

## Maintainer actions
- The OK for each real release after v0.1.0, after a green dry run (`process.md`, "Releases").
- After a failed push row or index: delete the untested and orphaned package versions the coordinator names.
- Org setting "Package creation: Public" was enabled to publish the packages; whether to switch it off again is the maintainer's choice (existing public packages should stay public; check after switching).
