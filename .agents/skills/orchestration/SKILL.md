---
name: orchestration
description: Run several agent sessions on opentide at once without making them wait on each other - branches per PR rather than per session, the merge steward's loop (update, merge, notify the owner), changelog series, review tiers chosen by what a change touches, environment prerequisites set up front, how blocked sessions surface, when to re-plan, and briefs that carry their precedent. Use when starting, steering or reviewing multi-session work, or when work feels sequential.
---

# Orchestration - parallel sessions, one quality bar

The quality bar does not change with the number of sessions: every fix still has a regression
test that fails without it ([`review-checklist`](../review-checklist/SKILL.md)); an engine change
still proves its output unchanged with a differential, or, when it means to change output, shows
the reviewed snapshot changes; performance work still brings its numbers. What this skill removes
is the waiting **between** those steps: sessions idle on merges they were not told about, fixes
queued behind each other on one branch, every queued PR conflicting on the changelog.

## 1. Branches belong to PRs, not to sessions

- A session may open as many branches as it has independent PRs: `<type>/<slug>` per PR, each cut
  from the current base. Never give a worker a single fixed push branch: its independent fixes
  then queue behind each other's CI and review.
- Stack only when the second PR needs the first's code; otherwise branch both from the base.
- Prepare the next PR locally while the current one is in CI or review.

## 2. The merge steward's loop

One session merges; owners never wait on it silently.

1. Take PRs in priority order: blockers of other PRs first, then the oldest green and reviewed PR.
2. When a green, reviewed PR's only gap is newer base commits with no conflict, update it with
   GitHub's "Update branch" **merge** option (never "Update with rebase", which force-pushes),
   and only when the owner's session is idle or has said it is not pushing. Tell the owner to
   `git pull` before their next push. Update one PR at a time; updating every PR after
   each merge only wastes gate runs.
3. Merge with the base's method: merge commits on `integration/*`
   ([`unified-core.md`](../../../docs/internal/unified-core.md)), the repository's setting on
   `development`. Pin the head SHA so a late push is never merged unreviewed.
4. **After every merge, message the owner of every PR or branch waiting on it**: "merged #N
   (sha); you're unblocked". An owner never discovers a merge by polling.
5. A conflict or a red gate after an update goes back to the owner with the failing check.
6. "Closes #N" does not fire on a non-default base. Close an issue by hand only when the merged
   PR's body says it fixes the issue in full: reason "completed", and a comment naming the PR, its
   merge commit and the base (on `integration/*` the fix reaches `development` later). A partial
   fix gets a progress comment and the issue stays open.

## 3. Changelog series

[`release-notes`](../release-notes/SKILL.md) decides what gets an entry: refactors get none. A
series of user-visible performance PRs that would each add an entry at the same spot in
`CHANGELOG.md` or `crates/CHANGELOG.md` conflicts on every merge. Such a series may instead defer
to one consolidated entry, when:

- a tracking issue lists the series, and each PR body says "changelog: deferred to #<issue>";
- that issue is a sub-issue of the release's tracking issue, so the release cannot close with the
  consolidated PR, written to `release-notes`, still open.

Fixes and features that change user-visible behaviour keep their own entry in their own PR.

## 4. Review chosen by what a change touches

Self-review is the exception, for prose only; when in doubt, take the independent review.

| Change | Review |
|---|---|
| Only prose: `docs/` pages, skills other than this one, the steward skill and `review-checklist`, and code comments | The author's own adversarial pass against [`review-checklist`](../review-checklist/SKILL.md), noted in the PR body |
| Everything else, whatever its size: any code, test, fixture, snapshot, corpus, catalog, budget, ledger or oracle exception; the workspace and tool configuration (`Cargo.toml`, `Cargo.lock`, `clippy.toml`, `rustfmt.toml`, `pyproject.toml`, `.config/`); `.github/` and `scripts/`; the CLI, MCP or SDK surface; a change to this skill, the steward skill or `review-checklist` | An independent adversarial review, posted on the PR, before merge |
| Performance work | Row 2 plus the numbers: instructions and allocations from `cargo xtask throughput`, wall time at one thread and at the default thread count, a work-count test that fails on the old path, and a byte-identical differential against the base commit |

Run the review while CI runs, not after it.

## 5. Environment before work

Set these up before the first session starts, not when a session hits them:

- **Vendor oracles:** what [`scripts/engine/oracles/README.md`](../../../scripts/engine/oracles/README.md)
  lists for the languages in scope (.NET for Kusto.Language, Java and Maven for Elasticsearch's
  parser, Docker for the live servers).
- **Network:** the hosts the work needs on the environment's allow list, such as
  learn.microsoft.com and www.elastic.co for the vendors' references, and the package
  registries the toolchains fetch from.
- **Disk:** one Cargo target pool per worktree ("Parallel agents" in [`AGENTS.md`](../../../AGENTS.md)),
  sized to the disk; delete pools a finished worktree left.
- **Push permissions:** each session may push its own `<type>/*` branches without a prompt, and
  never `development` or `integration/*`. The user sets these; an agent never changes its own
  permission settings.

## 6. Blocked is a message, never a prompt

- A worker that needs a decision messages the orchestrator with the question, the options and its
  recommendation, then continues with whatever does not depend on the answer. It never waits on an
  interactive question nobody is watching.
- The orchestrator answers promptly (by default within its next turn) and decides what it can;
  only decisions that are the user's (product scope, outward actions, publishing) go to the user.
- Workers that share files may agree ownership directly. The owner of the file records the
  agreement in its PR body and tells the orchestrator; a disagreement goes to the orchestrator.
- A session silent with work left (by default for an hour) gets a check, which reads its status
  rather than waiting for the next scheduled round.

## 7. Re-plan when scope grows

Profiling and oracles find real problems, and fixing them before a release is right. When a
finding adds more than two PRs, re-plan instead of queueing them behind one session: split by file
ownership across free sessions, and say what moves the finish line.

## 8. A brief carries its precedent

A worker meets the bar it is shown. A brief that states only what to change gets a change that is
correct and thin: RFC 0021 (Microsoft Defender) shipped with its decisions right but without the
full YAML shape, the field table or the Graph mapping that every earlier platform RFC carries,
and the owner sent it back.

- **Name the precedent.** Every brief for a spec, RFC, platform, connector, docs page or skill names
  the two or three closest existing ones by path ("as detailed as `rfcs/00NN-exabeam...`") and
  says to match their sections and depth, not only their format.
- **State the artefacts, not only the decisions.** For a platform RFC or spec: the complete and the
  minimal YAML block, a field table (type, required, default, allowed values, vendor property), the
  exact request the connector sends for the complete example, the deploy lifecycle per status, every
  validation code with an example, the upgrade path, alternatives and risks. Other kinds of work
  list theirs the same way.
- **Review against the precedent.** Before merging, put the result beside the precedent it named:
  a section the precedent has and the result lacks is a finding, however correct the rest is. CI
  checks that a document builds; only this comparison checks that it is complete.
- When the repository has its own authoring guide or template (opentidehq/specifications' RFC
  guidance), the brief points to it and the review checks it was followed; a gap found in review
  goes back into that guide too.

## Anti-patterns

- One push branch per session, so a session's independent fixes go up one after another.
- Owners idle after the PR they waited on has merged.
- Every queued PR conflicting on the changelog after each merge.
- A full independent review on a docs fix while CI also waits; or, the other way, a small parser
  fix merged on the author's review alone.
- Relaying vendor-oracle runs through another session because a container lacks a toolchain.
- A worker blocked on an interactive question in a session nobody is watching.
- A brief that lists the decisions but no precedent, and a review that checks only that CI is green:
  the result is correct and thinner than everything before it.
