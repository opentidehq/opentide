# Documentation authoring guide

OpenTide documentation lives in this directory and is structured for a future **Fumadocs** site with four top-level sections (sidebar tabs):

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

## Agent maintenance

Agents working on documentation should read [`.agents/skills/docs-maintenance/SKILL.md`](../.agents/skills/docs-maintenance/SKILL.md).

## Fumadocs site repository

Scaffolding for the future website lives in [`fumadocs/`](./fumadocs/). Copy `source.config.ts.example` into the site repo and point `dir` at this `docs/` folder (git submodule, sparse checkout, or CI sync).

## Local preview (interim)

Until the Fumadocs site ships, preview with MkDocs Material:

```bash
uv sync --group docs
uv run mkdocs serve
```

Nav is defined in [`mkdocs.yml`](../mkdocs.yml) at the repository root.
