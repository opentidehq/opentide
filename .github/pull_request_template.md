## What and why

<!-- The user-visible problem or goal, and the approach. Link the issue. -->

## Verification

- [ ] A regression test fails without this change and passes with it (or: why none applies)
- [ ] `scripts/ci-local.sh --full` passes locally

## Checklist

- [ ] User-visible change: entry under `## [Unreleased]` in `CHANGELOG.md`
- [ ] CLI / MCP / SDK surface change: `docs/` updated
- [ ] No new `# noqa` / `# ty: ignore` without a reason on the same line
- [ ] Checked against [`review-checklist`](../.agents/skills/review-checklist/SKILL.md)
