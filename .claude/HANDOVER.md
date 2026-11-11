# Handover

Current state only. At session end replace these sections; never append. History lives in PRs, issues and git.

## Last release
- None. No release is possible before #5 (release pipeline).

## Open PRs
- None.

## Open tickets
- **0.1.0 (Foundation):**
  - #3 prototype: Dovecot 2.4 proxy routes users to two mail stores (`ready`);
  - #4 prototype: Dovecot 2.4 reads mail encrypted by mailcow's `mail_crypt` (`ready`);
  - #7 Keepia brand, in keepia/design-system (`ready`);
  - #2 architecture plan (`docs`; defines the resource budget in `docs/development/architecture.md`);
  - #5 Docker images and release pipeline;
  - #6 Go skeleton: service, CLI, Postgres migrations, health endpoint.
- **Not in a milestone:** #13 migration runbook and import command: mailcow to Keepia Mail (new).

## Active decisions
- **Operating model:** one shared instance run by the operator; customers are separated by groups.
- **Public, MIT licence.**
- **Brand** lives in keepia/design-system (#7, 2026-11-11).
- The reference installation moves from mailcow to Keepia Mail with 1.0.0 (#13).
- **Coordinator autonomy** (maintainer, 2026-11-11): as in `CLAUDE.md`.
- **Merge mechanics:** squash merge pinned to the reviewed head SHA (`expectedHeadSha`); a branch behind `main` is refused for required checks, so bring `main` in first.
- **CI before the Go jobs:** every job in `ci.yml` counts as required for merges until the ruleset lists it. #6 adds `test`, `lint` and `vulncheck`; #5 adds `docker` and `compose`. After their first green run the maintainer adds them to the ruleset.
- **Workflow changes:** workflow changes and changes to the pin check (`tools/check-action-pins/`) get `second-review`.
- **Resource budget:** plans state memory and CPU per role and for all roles on one server, against `docs/development/architecture.md` once #2 is merged.

## Maintainer actions
- None open, except deleting the remote branch `proof/secret-scan`.
