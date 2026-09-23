# Documentation authoring guide

OpenTide documentation lives in this directory and is published on **[opentide.org](https://opentide.org/docs)** by [OpenTideHQ/website](https://github.com/OpenTideHQ/website). Four top-level sections become sidebar tabs:

| Tab | Directory | Audience |
|-----|-----------|----------|
| Usage | `usage/` | Human operators — setup, workflows, concepts |
| CLI | `cli/` | Command-line reference |
| MCP | `mcp/` | Agent and editor integrations |
| SDK | `sdk/` | Python API consumers |

Internal maintainer docs (test plan, publishing) live in `internal/` and are excluded from the public site tree.

## Conventions

### Frontmatter

Every page starts with YAML frontmatter:

```yaml
---
title: Page title
description: One sentence for cards, SEO, and LLM context
---
```

Optional fields for the Fumadocs site:

```yaml
icon: Terminal          # Lucide icon name
full: true              # full-width layout
---
```

### Navigation (`meta.json`)

Each folder may contain `meta.json` to control sidebar order. Root tabs set `"root": true`.

```json
{
  "root": true,
  "title": "CLI",
  "description": "Technical CLI reference",
  "icon": "Terminal",
  "pages": ["index", "global-options", "setup"]
}
```

Use Fumadocs separators: `"---Section name---"`. External links: `"external:[Label](https://…)"`.

### File names

- Use **kebab-case** filenames.
- Folder index pages: `index.md`.
- Prefer `.md` over `.mdx` unless a page needs React components.

### When code changes

Update docs in the **same PR** when you change:

| Code area | Doc location |
|-----------|--------------|
| CLI commands / flags | `docs/cli/` |
| MCP tools / resources | `docs/mcp/` |
| Public Python API | `docs/sdk/` |
| Setup / onboarding flows | `docs/usage/` |
| Platform capabilities | `docs/usage/concepts/platforms.md` |

Run `scripts/validate-docs.sh` before pushing doc changes.

### Output samples

Show output you captured, not output you expect. Pair a `text` or `json` fence with the command that prints it by naming the command in the fence's info string, and add `exit=N` when the command is meant to fail:

````markdown
```bash
opentide deploy metadata --platform splunk
```

```text output-of="opentide deploy metadata --platform splunk" exit=2
FATAL: Metadata deployment is not implemented for splunk
```
````

`tests/test_docs/test_docs_commands_golden.py` runs every paired command against a repository scaffolded as in the [tutorial](./usage/tutorial.md), with vendor APIs stubbed. It fails when:

- the command is not in a shell fence on the same page, or is not one the harness runs (`validate`, `lint`, `info`, `generate`, `deploy`);
- the command returns a code other than `exit=` (`0` when absent), or a non-zero `exit=` sits in a section that never says it exits `` `N` ``;
- a `text` line is not printed whole and in order, reading stdout and stderr interleaved as a terminal shows them. Write the `--no-color` view; a colour run must carry the same lines, with its rules and FATAL panel read back as `== Title ==` and `FATAL: …`;
- a `json` value differs from the document returned. Objects may return keys the sample leaves out, and `"..."` stands for any value.

Neither attribute renders: Fumadocs reads only `title`, `tab`, `noCopy` and `lineNumbers` from fence meta, and GitHub reads only the language.

## Agent maintenance

Agents working on documentation should read [`.agents/skills/docs-maintenance/SKILL.md`](../.agents/skills/docs-maintenance/SKILL.md).

## Fumadocs site repository

**Build and deploy are owned by [OpenTideHQ/website](https://github.com/OpenTideHQ/website)** — not this repo. This repository only ships markdown content and structural validation.

Scaffolding notes: [`fumadocs/`](./fumadocs/). The website repo syncs `docs/` at build time.

## Validation

```bash
scripts/validate-docs.sh
```

CI runs the same check via [`.github/workflows/docs.yml`](../.github/workflows/docs.yml) on docs changes.
