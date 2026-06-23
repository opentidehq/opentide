# OpenTide — GitHub Copilot

Read [`AGENTS.md`](../AGENTS.md) first — it is the coding-agent entry point for this repository.

## Skills

| Task | Skill |
|------|-------|
| jj VCS (all work, including stacks) | [`.agents/skills/jujutsu/SKILL.md`](../.agents/skills/jujutsu/SKILL.md) |
| uv, pre-commit, ci-local | [`.agents/skills/uv/SKILL.md`](../.agents/skills/uv/SKILL.md) |
| Ruff | [`.agents/skills/ruff/SKILL.md`](../.agents/skills/ruff/SKILL.md) |
| ty | [`.agents/skills/python-typing/SKILL.md`](../.agents/skills/python-typing/SKILL.md) |
| CodeQL | [`.agents/skills/codeql/SKILL.md`](../.agents/skills/codeql/SKILL.md) |
| pytest patterns | [`.agents/skills/python-testing-patterns/SKILL.md`](../.agents/skills/python-testing-patterns/SKILL.md) |
| coverage | [`.agents/skills/pytest-coverage/SKILL.md`](../.agents/skills/pytest-coverage/SKILL.md) |
| GitHub Actions | [`.agents/skills/github-actions-templates/SKILL.md`](../.agents/skills/github-actions-templates/SKILL.md) |

**Version control:** jj only — not `git commit`, not Graphite. Push with `jj git push --bookmark`; open PRs with `scripts/jj-submit.sh` or `scripts/jj-stack-submit.sh`.
