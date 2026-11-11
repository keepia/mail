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
`.github/workflows/` or `tools/check-action-pins/`) also get a second,
independent session review by a separate reviewer agent that does not see the
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
| `breaking` | by hand | Manual upgrade steps; makes a major release. |
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
- Version check (from #5, the release pipeline; until then no release is
  possible): the dry run's proposed version (`scripts/next-version.sh`,
  label based) must equal the milestone title. If it differs (for example a
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

The release workflow comes with #5.
