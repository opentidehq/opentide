# {name}

{description}

**Organisation:** {org}

This repository uses [opentide](https://pypi.org/project/opentide/): spec-driven development for agentic detection engineering. Read [`AGENTS.md`](AGENTS.md) for the full workflow.

## Skills

| Task | Skill |
|------|-------|
| Validate, generate, deploy | [`.agents/skills/opentide-detection-rule/SKILL.md`](.agents/skills/opentide-detection-rule/SKILL.md) |

## Quick start

```bash
opentide validate
opentide generate
{deploy}
```

## Running opentide

- Run `opentide --json <command>`: stdout is one JSON document. `opentide --json commands` lists every command and option.
- Branch on the exit code, then on `failure.code`: `0` success, `1` failure (`issues_found`, `command_failed`), `2` usage error or a check that could not run, `3` partial `share`.
- Apply each finding's `fix.edits` (replace `[column, end_column)` on `line`, 1-based, with `replacement`); `safe: true` edits are typo fixes. Run `opentide explain <code>` for the others.
- Follow `next_actions` (`{command, reason}`).
- Loop: draft, then `opentide --json validate --file <file>` until `ok` is `true`, then `opentide --json deploy --dry-run --strategy PREVIEW --all`. People review, merge and deploy.
