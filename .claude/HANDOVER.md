# Handover

Current state only. At session end replace these sections; never append. History lives in PRs, issues and git.

## Last release
- None. No release is possible before #5 (release pipeline).

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
- **CI jobs not yet in the ruleset:** `test`, `lint`, `vulncheck` (#6) and `docker` (#5 part 1) count as required for merges until the ruleset lists them; #5 part 3 adds `compose` the same way.
- **Images:** pins, privileges, healthcheck rules and the check's threat model in `.claude/rules/docker.md`; images are built only through `check-image-pins -bake-local` (`make images`) and CI's checked `docker/bake-action` step; `scripts/ci-docker-mirror.sh`, `ci-pull-images.sh` and `check-go-toolchain*.sh` stay byte-identical with mail-archive.
- **Workflow changes:** a change to `.github/workflows/`, `tools/check-action-pins/`, the Makefile's `workflows`/`workflows-test` targets, or the `go.yaml.in/yaml/v3` line in `go.mod` gets `second-review`.
- **Resource budget:** plans state memory and CPU per role and for all roles on one server, against `docs/development/architecture.md` once #2 is merged.

## Maintainer actions
- Add `test`, `lint`, `vulncheck` to the `main` ruleset (#6), after their first green run; `docker` (#5) after its first green run.
- Delete the remote branch `proof/secret-scan`.
