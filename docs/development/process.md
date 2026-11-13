# Issues, plans and releases

Work goes through four steps: **issue → plan → approval → pull request**.
Nothing is implemented before its plan is approved. The coordinator picks
what gets planned next; an approved plan decides what gets built. The
maintainer decides new goals, milestone scope, releases and anything that
widens access or weakens security or privacy; UI wording, technical
trade-offs and small product details inside an approved goal are the
coordinator's ([`CLAUDE.md`](../../CLAUDE.md),
"Coordinator autonomy"). Labels carry these decisions.

## 1. Issue

Every change starts as a GitHub issue:

- **Bug report** and **Feature request** templates ask for what is needed
  (steps and version for bugs, problem and "done when" for features).
- Findings from test reports become issues, one per topic, with a link to
  the report.
- Security problems go to the
  [private vulnerability report](https://github.com/keepia/mail/security/advisories/new),
  not to a public issue.

## 2. Plan

The coordinator (or the maintainer) labels an issue **`plan`** when it picks
it next from the backlog. A Claude session writes the plan as a `## Plan`
comment on the issue, and the label changes to **`review`**. A plan covers:

- the approach and the files or components it touches,
- API, database or behavior changes (a schema change means `db-migration`),
- how it will be tested,
- open questions and decisions to make,
- the expected size (one pull request or several).

## 3. Review and approval

An independent plan-reviewer agent (never the planner) reviews the plan; the
maintainer may read it too. Both ask questions or for changes in the issue,
and the plan is updated in place. When it is good, the reviewer or the
maintainer replaces `review` with **`ready`**. Only `ready` issues are
implemented.

A plan with several parts gets one sub-issue per part, titled
`<what> (#N, part K)`, created by the planner or the coordinator when the plan
is posted. The `ready` on the main issue covers all parts, and the
main issue closes with the last part.

The order of `ready` issues is chosen during implementation, with a short
reason (dependencies between issues, risk, size). Changes to an approved plan
that come up during the work are noted in the issue before the pull request.

## 4. Pull request

Each issue (or part of a plan) gets its own branch and pull request. The
description says `Closes #N` (and "Part K of #N" for a part), so merging closes
the issue. Labels follow the [label table](#labels). After an approving
review and green required checks, the coordinator merges with squash; there
is no auto-merge.

Every pull request with app code gets a session review. Risky pull requests
(deletes, schema changes, rewriting user data, auth and sessions, external
services, changes to the serving layer: static file serving, response
headers, CSP, routing, mail routing and placement, the control-plane/agent
trust boundary, encryption at rest and keys, spam, virus, rate-limit and ban
policy, container privileges and networking, and changes to
`.github/workflows/`, `tools/check-action-pins/`, the Makefile's
`workflows`/`workflows-test` targets or the `go.yaml.in/yaml/v3` line in
`go.mod`) also get a second, independent session review by a separate reviewer agent that does not see the
first review beforehand. The coordinator labels each of them
**`second-review`**, every pull request that changes the schema included; the
label is a marker and triggers nothing. Pull requests without app code that
are not risky (docs, other CI files, test-only) need one session review and
green required checks.

Pull requests that can weaken the secret scan are merged only after the
maintainer's explicit OK, noted on the pull request. This covers
`.gitleaksignore`, `.gitleaks.toml` and files it extends, a new
`gitleaks:allow` comment, `.github/workflows/secrets.yml`,
`scripts/secret-scan-*` and the gitleaks variables and targets in the
`Makefile`. The reviewer flags any such change as blocking until the OK is
there. The OK names the changed entries, never secret values.

A non-blocking review finding becomes a follow-up issue, labelled
**`followup`**, only when the reviewer names a realistic case likely to occur
soon. The coordinator creates it after the merge, and its body names the pull
request or review it comes from. Every other non-blocking remark stays in the
review and is done with it.

## Agents, rules and handover

The Claude roles are defined in `.claude/agents/`: `implementer.md`,
`reviewer.md` and `plan-reviewer.md`. The coordinator starts them as agents,
or, where a session does not offer them, as general agents told to act as the
role in that file. Lessons that apply to certain files live in
`.claude/rules/*.md`; each rule names its files in `paths:` and loads when a
matching file is read or edited, and the agents read the matching rules
themselves before they start. The GitHub commands per operation are in
`.claude/github-operations.md`.

`.claude/HANDOVER.md` holds only the current state: open pull requests, open
tickets, active decisions and maintainer actions. A session reads it at start
and replaces it at the end, never appending; history lives in pull requests,
issues and git. Follow-ups are open issues labelled `followup`, queried when
needed and not read at start.

## Labels

Labels are defined in `.github/labels.json` and synced to GitHub when that
file changes on `main`.

| Label | Set by | Meaning |
|---|---|---|
| `plan` | coordinator or maintainer | Please write an implementation plan (Claude session). |
| `review` | planner | The plan is posted and waits for review. |
| `ready` | plan reviewer or maintainer | The plan is approved; the issue may be implemented. |
| `second-review` | coordinator or maintainer | Risky pull request: needs a second, independent session review (a marker; it triggers nothing). |
| `db-migration` | automatically | Schema change; back up before upgrading. Makes at least a minor release. |
| `breaking` | by hand | Manual upgrade steps. Before 1.0.0 it makes a minor release (the 0.x rule, `scripts/version-policy.sh`); from 1.0.0 a major release. |
| `feature`, `bug`, `docs`, `chore` | template or by hand | Kind of change; `feature` makes at least a minor release. |
| `security` | by hand | Security hardening (never an undisclosed vulnerability). Kind label; does not change the version (a patch release unless other labels raise it). |
| `dependencies` | Dependabot | Dependency update. |
| `followup` | coordinator | Non-blocking finding from a review, CI or the day's work; its body names the source. |

Label changes do not notify anyone by themselves: after setting `plan` or
`ready`, say so in the chat with the implementer (for example "plan #18" or
"ready: #18, #19").

## Milestones

Releases are planned with GitHub milestones: one milestone per planned
release, titled `0.Y.Z` before the first stable release and `X.Y.Z` after it
(no `v`), with a one-sentence goal as description.

- The coordinator proposes the scope and order of a milestone; the
  maintainer confirms. Then the coordinator assigns the issues (the main
  issue and its sub-issues) and keeps the milestone current. Adding or
  removing an issue after the confirmation needs the maintainer's OK, except
  for bugs in the milestone's own work. A pull request gets the milestone of
  its issue.
- A release is made when every issue of its milestone is closed and CI on
  `main` is green.
- Version check: the dry run's proposed version (`scripts/version-policy.sh`
  over `scripts/next-version.sh`, label based) must equal the milestone
  title. If it differs (for example a
  `breaking` pull request slipped in), the coordinator renames the milestone
  to the proposal and tells the maintainer. The one exception: when only
  reverted pull requests raise the proposal, the `version` input lowers it
  to the milestone title, and the coordinator says so on the release.
  Otherwise never use the `version` input to go below the proposal.
- Patch releases: a bug goes into the next patch milestone (`X.Y.Z+1`).
  Releases come from `main`, without release branches and without backports,
  so once the first pull request of the next minor or major milestone is
  merged, every later release is at least that version; open bug fixes then
  move into that milestone. The coordinator releases pending patch
  milestones before merging the first pull request of the next minor when
  that is reasonable.
- After the release the coordinator closes the milestone. An issue closed as
  not planned is removed from its milestone.

Commands: `.claude/github-operations.md`.

## Releases

`.github/workflows/release.yml` releases from `main`, started by hand
(Actions → Release → Run workflow on `main`). Its jobs, tags and checks
are in [index.md, "Releases"](index.md#releases). The coordinator runs
it; the coordinator never deletes a package version and changes no
package setting.

1. **Preconditions.** Every issue of the milestone is closed and CI on
   `main` is green.
2. **Dry run first.** The coordinator runs the workflow with the default
   `dry_run: true` and posts the run's summaries on the milestone's main
   issue: the version with its rule and the pull request table, every
   image with its tags and platforms, the upstream images by digest, the
   ten build rows with their verified images and tested configs, the ten
   push-rehearsal rows (pushed by digest to the job's local registry;
   "pushed config = tested config", read back from `localhost:5000`), the SBOM and
   source table (10 of 10), the bundle listing and the notes head. A dry
   run holds no write token and publishes nothing. The version must equal
   the milestone title (the version check above).
3. **The real release.**
   - **`v0.1.0` is pre-approved** (maintainer decision 6845990778 on #27):
     the coordinator starts it with no further confirmation once the dry
     run on `main` is green, on the same commit as that dry run, with every
     image built (all ten build and push-rehearsal rows) and the sums and
     SBOMs complete (10 of 10, the exact asset list, `SHA256SUMS`). If
     anything differs from what is expected (another version, a missing
     row or SBOM, a red or skipped job, another commit), the coordinator
     stops and reports to the maintainer instead.
   - **Every later real release needs the maintainer's OK.** The
     coordinator asks through AskUserQuestion, with the version, the link
     to the green dry run, the image list, for 0.x the line "X.Y.Z is not
     a working mail server", and anything new since the last release. The
     OK is noted on the issue. Only then does the coordinator start the
     workflow with `dry_run` unticked, on the same commit as the dry run.
   - The `version` input is used only as the version check allows; 1.0.0
     only with the OK.
4. **After the release:**
   - check the release page: the notes, and the assets: the bundle
     `keepia-mail-X.Y.Z.tar.gz`, the ten `sbom-<image>-<arch>.spdx.json`,
     `sources.json`, `SOURCES.md`, `notes.md` and `SHA256SUMS`;
     `sha256sum -c SHA256SUMS` passes on the downloaded assets;
   - for each of the five images, `gh attestation verify
     oci://ghcr.io/keepia/mail-<name>:X.Y.Z --owner keepia`, and for one
     platform digest the SBOM (`--predicate-type
     https://spdx.dev/Document/v2.3`);
   - `docker buildx imagetools inspect ghcr.io/keepia/mail-<name>:latest`
     names the same digest as `X.Y.Z`;
   - **after the first release, the maintainer makes the five GHCR
     packages** (`mail`, `mail-postfix`, `mail-unbound`, `mail-olefy`,
     `mail-sogo`) **public and links them to keepia/mail** (package
     settings). New packages may start private; until then the bundle's
     `docker compose pull` fails for anyone else. Later releases check that
     they still are;
   - update the HANDOVER "Last release" line and close the milestone.
5. **Failure cases, per job.** "Re-run failed jobs" keeps the run's
   commit, inputs and the outputs of the jobs that passed; "Re-run all
   jobs" starts over on the same commit.
   - `version`, `build` or `push-rehearsal` failed: nothing is published.
     Fix the cause on `main` and start a new run.
   - `push` failed before its bake step: that row pushed nothing; "Re-run
     failed jobs".
   - **`push` failed at `-verify-pushed` with a mismatch (the pushed
     config is not the tested one, or `the registry holds other content
     than pushed.tar`).** BuildKit pushed during the bake step, so that row's
     **untested image is in GHCR by digest**, untagged. Nothing is tagged,
     attested or released. The coordinator stops and reports to the
     maintainer the digest the error names, and the digests of the rows
     that passed in that attempt (their `digest-*` artifacts and step
     outputs): those are tested but **orphaned**, because the next cold
     build gives other layers. **The maintainer deletes those package
     versions** (package settings, "Manage versions"). Then the cause is
     fixed (an evicted `release-` cache entry, or a step that is not
     reproducible) and the release restarts with "Re-run all jobs": only
     `build` seeds the cache. No tag exists yet, so `version` gives the
     same version.
   - **`push` failed at `-verify-pushed` with `the registry read failed`
     only** (#75): every check of `pushed.tar` passed, so the row's image
     is the tested one; only reading it back from GHCR failed (a network
     error, a timeout, an answer buildx does not know). That is a read
     error, not a mismatch: nothing is deleted for it. The coordinator
     stops and reports the error text to the maintainer, who decides
     between "Re-run failed jobs" (the rebuild from the cache pushes the
     same digest again) and a reviewed fix.
   - `index` failed: fix the cause, then "Re-run failed jobs".
     `-publish-index` keeps an `X.Y.Z` that holds exactly the expected
     content and refuses any other; in that case the maintainer deletes
     the package version. If the fix needs a new commit, start a new run:
     the first run's pushed digests are orphaned and go on the deletion
     list. Two limits of its "not found" (#71, deviation 7 and review A
     N4): `X.Y.Z` counts as absent only when two inspections in a row give
     buildx's exact `ERROR: <ref>: not found`, so a registry that wrongly
     answers that way twice could let it write over an existing tag; the
     `version` job's check that `vX.Y.Z` and its release do not exist keeps
     an existing `X.Y.Z` to the leftover of a failed run of the same
     version. And that exact text was measured on `registry:3` and, read
     only and anonymously, on GHCR through buildx 0.38.1 (#72 review A:
     `ERROR: <ref>: not found`); the first real release confirms it with
     the token. Another text fails closed (an inspect error, nothing
     created); the coordinator reports it, and the fix is a reviewed change
     to `inspectError`.
   - `attest` or `attest-assets` failed: `X.Y.Z` is in GHCR, but there is
     no release and `latest` has not moved. "Re-run failed jobs".
   - `release` failed: its last step removes the tag and the draft this
     run created. "Re-run failed jobs". Its tag step refuses to start
     while any release of the tag exists, a draft included, so that step
     never deletes a draft it did not create; a leftover draft from
     elsewhere is deleted by hand first.
   - `latest` failed: the release is published, and `latest` may still
     point at the previous release for some images. Fix the cause, then
     "Re-run failed jobs": the moves are idempotent and only go forward.
   - **A run shown as cancelled before any job started:** GitHub keeps at
     most one pending run in the concurrency group `release`. A third
     dispatch while one is pending cancels the pending one, which has done
     nothing. That is no failure: start it again once the running run has
     finished. "Re-run failed jobs" joins the same group.
   - **A run from a branch** fails at its first step ("Started on main").
     A branch can change its own `release.yml`, which rule 7 checks only on
     pull requests: that residual risk is for review.
6. **Abandoning a release.** Before the `latest` job ran, the maintainer
   deletes the release (if any), the tag and the five package versions.
   After it, the maintainer first moves `latest` back by hand, for each
   image, after a `docker login ghcr.io` with a token that has
   `write:packages`:

   ```sh
   docker buildx imagetools create -t ghcr.io/keepia/mail-<name>:latest ghcr.io/keepia/mail-<name>:<previous X.Y.Z>
   ```

   (`ghcr.io/keepia/mail` for the Keepia image), then deletes the release,
   the tag and the package versions. At the first release there is no
   previous version: deleting the package versions removes `latest` too.
   The workflow has no backward path for `latest`.
