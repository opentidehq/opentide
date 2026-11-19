---
name: orchestration
description: Run several agent sessions on opentide at once without making them wait on each other - branches per PR rather than per session, the merge steward's loop (update, merge, notify the owner), changelog series, review tiers sized to the change, environment prerequisites set up front, how blocked sessions surface, and when to re-plan. Use when starting, steering or reviewing multi-session work, or when work feels sequential.
---

# Orchestration - parallel sessions, one quality bar

The quality bar does not change with the number of sessions: every fix still has a regression
test that fails without it ([`review-checklist`](../review-checklist/SKILL.md)), every engine
change still proves its output identical and its cost measured. What this skill removes is the
waiting **between** those steps. Each rule below comes from a loss measured on the
unified-core performance and syntax-gap series (#1571), where a 30-minute fix routinely took
2 hours end to end.

## 1. Branches belong to PRs, not to sessions

- A session may open as many branches as it has independent PRs: `<type>/<slug>` per PR, each cut
  from the current base. Never give a worker a single fixed push branch: its independent fixes
  then queue behind each other's CI and review.
- Stack only when the second PR needs the first's code; otherwise branch both from the base.
- Prepare the next PR locally while the current one is in CI or review.

## 2. The merge steward's loop

One session merges; owners never wait on it silently.

1. Take PRs in priority order: blockers of other PRs first, then the oldest green and reviewed PR.
2. When a green, reviewed PR's only gap is newer base commits with no conflict, update it
   (GitHub "Update branch", a merge commit, never a force-push) and merge it when its gate passes.
   Update one PR at a time; updating every PR after each merge only wastes gate runs.
3. **After every merge, message the owner of every PR or branch waiting on it**: "merged #N
   (sha); you're unblocked". An owner never discovers a merge by polling.
4. A conflict or a red gate after an update goes back to the owner with the failing check.
5. Close the issue a merged PR fixes, with a one-line comment naming the PR and its merge commit.
   "Closes #N" does not fire on non-default bases.

## 3. Changelog series

A series of related PRs that each add an entry at the same spot in `CHANGELOG.md` or
`crates/CHANGELOG.md` conflict on every merge. For a performance or refactor series, the PRs
carry no changelog hunk and say "changelog: deferred to the consolidated entry"; one
consolidated PR, written to [`release-notes`](../release-notes/SKILL.md), lands last. Fixes and
features that change user-visible behaviour keep their own entry.

## 4. Review sized to the change

| Change | Review |
|---|---|
| Docs, comments, a test-only change, or a fix under ~50 lines with its regression test | The author's own adversarial pass against [`review-checklist`](../review-checklist/SKILL.md), noted in the PR body |
| Engine logic, a parser or grammar, the CLI/MCP/SDK surface, CI and gates | An independent adversarial review, posted on the PR, before merge |
| Performance work | The above plus the numbers: instructions and allocations from `cargo xtask throughput`, wall time at 1 and N threads, a work-count test that fails on the old path, and a byte-identical differential |

Run the review while CI runs, not after it.

## 5. Environment before work

Set these up before the first session starts, not when a session hits them:

- **Vendor oracles:** .NET (Kusto.Language), Java and Maven (Elasticsearch's ES|QL parser), and
  Docker (live Elasticsearch for `probes.py`). See [`catalogs`](../catalogs/SKILL.md).
- **Network:** the doc sites the work reads (learn.microsoft.com, www.elastic.co) and the
  registries on the allow list.
- **Disk:** one Cargo target pool per worktree ("Parallel agents" in [`AGENTS.md`](../../../AGENTS.md)),
  sized to the disk; delete pools a finished worktree left.
- **Push permissions:** the branches a session will push are allowed in its settings, so a push
  never waits on a human approval nobody is watching.

## 6. Blocked is a message, never a prompt

- A worker that needs a decision messages the orchestrator with the question, the options and
  its recommendation, then continues with whatever does not depend on the answer. It never waits
  on an interactive question nobody is watching.
- The orchestrator answers within one turn and decides what it can; only decisions that are the
  user's (product scope, outward actions, publishing) go to the user.
- Workers that share files agree on ownership directly with each other, not through the
  orchestrator.
- A session silent for an hour with work left gets a check; the check reads its status rather
  than waiting for the next scheduled round.

## 7. Re-plan when scope grows

Profiling and oracles find real problems, and fixing them before a release is right. When a
finding adds more than two PRs, re-plan instead of queueing them behind one session: split by
file ownership across free sessions, and say what moves the finish line.

## Anti-patterns seen

- One push branch per session, so six fixes went up one after another.
- Owners idle for hours after the PR they waited on had merged.
- Every queued PR conflicting on the changelog after each merge.
- A full independent review on a six-line fix.
- Relaying vendor-oracle runs through another session because a container lacked .NET.
- A worker blocked on an interactive question in a session nobody was watching.
