# Workflow

Roles: maintainer (human), coordinator (Claude: orders the backlog, plans, delegates, merges), implementer (one PR each), reviewer, plan-reviewer (never the planner). Agents: `.claude/agents/`; coordination and models: [pklnx/dev-process](https://github.com/pklnx/dev-process). All in Claude sessions on the subscription; no Claude GitHub Action.

Language: German with the maintainer; English on GitHub and in code. Every GitHub text ends with `— Claude, <role>`; no model names on GitHub.

## Coordinator autonomy
The coordinator decides alone and reports afterwards: UI wording, technical trade-offs, small product details inside an approved goal, tightening security. It asks the maintainer (AskUserQuestion, recommendation first, questions bundled) about new goals and milestone scope, releases, and anything that widens access or weakens security or privacy, including the guarantees in `SECURITY.md` (later `docs/reference/security.md`). It reports only at milestones and blockers, works toward the goal instead of asking for confirmation, and records its decisions for later review ("Coordinator decisions" in plans, PR and issue comments). Agents stop and report only for real product questions; technical choices they make and document.

## Ticket flow
1. Issue (template).
2. Coordinator or maintainer labels `plan` → `## Plan` comment (approach, files, data model, external services, tests, open questions, size); label becomes `review`.
3. A plan-reviewer agent reviews independently; it or the maintainer replaces `review` with `ready`. Only `ready` issues are built.
4. Several parts: one sub-issue per part, created with the plan, titled "<what> (#N, part K)", linked as GitHub sub-issue (by `id`, not number). The main issue's `ready` covers them; it closes with the last part.
5. One branch and PR per part; body "Closes #<sub>." and "Part K of #N.".
6. Review: a session reviewer for all app code. Risky PRs also get a second, independent session reviewer who has not seen the first; the coordinator marks them `second-review`. Risky are: deletes, schema changes (`db-migration`), rewriting user data, auth and sessions, external services, the serving layer (static files, response headers, CSP, routing), mail routing and placement, the control-plane/agent trust boundary, encryption at rest and keys, spam, virus, rate-limit and ban policy, container privileges and networking, and any change to `.github/workflows/` or `tools/check-action-pins/`. No app code and not risky (docs, other CI files, test-only): one session review (Sonnet) and green required checks.
7. Merge: approving review and green required checks; squash merge pinned to the reviewed head SHA. Before the merge a PR comment names the reports read and checks every Done-when item ("met" with evidence, or "after merge" with the step that checks it; dev-process `decisions.md`, Never 2). Closing an issue: a summary comment with the figures of dev-process `metrics.md` that ticks off every Done-when item. Never auto-merge; never change rulesets or repo settings. A PR touching the secret scan's allowlist or configuration (files: `docs/development/process.md`, "4. Pull request") merges only after the maintainer's explicit OK, asked via AskUserQuestion with the changed entries (file, rule id, path or fingerprint), never secret values; the OK is noted on the PR.
8. Releases are planned in milestones (`docs/development/process.md`, "Milestones").

Blocking in reviews only: crash, data loss or corruption, hang, wrong result in a main function, security or privacy problem, broken main flow, missing or failing test for new behaviour, plan or maintainer decision violated. Anything else: a `followup` issue if the reviewer names a realistic near-term case, else stays in the review.

## GitHub operations
Commands per operation: `.claude/github-operations.md`, read before the first GitHub write. An MCP `issue_write` labels update replaces the whole set.

## Rules
- Tests never touch real user data, credentials or the network. Secrets only in the secret store, never in chat or files.
- Every behaviour change has tests; a bug fix has a regression test that fails without the fix. Tests wait for signals, never for time.
- Locally run only the tests of what changed; CI runs everything.
- Plans state the memory and CPU cost per role and for "all roles on one server", against the resource budget in `docs/development/architecture.md` (#2). Until #2 is merged, the plan states the cost and the plan reviewer checks it against #2's plan.
- Agents never watch CI: push, open the PR, report; the coordinator waits for checks (GitHub operations).
- ≤3 tickets in parallel, ≤2 PRs in CI at a time.
- A flaky-test rerun gets a row in `docs/development/flaky-tests.md`; a test listed twice is fixed right away.
- After 3 review rounds that keep finding new holes in a heuristic: stop patching; rebuild it on a principle or give the maintainer options.

## Session handover
Start: read `.claude/HANDOVER.md`; follow-ups are open `followup` issues, queried when needed. End: replace its state, never append.
