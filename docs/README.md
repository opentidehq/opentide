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

**Build and deploy are owned by [OpenTideHQ/website](https://github.com/OpenTideHQ/website)** — not this repo. This repository only ships markdown content and structural validation.

Scaffolding notes: [`fumadocs/`](./fumadocs/). The website repo syncs `docs/` at build time.

## Validation

```bash
scripts/validate-docs.sh
```

CI runs the same check via [`.github/workflows/docs.yml`](../.github/workflows/docs.yml) on docs changes.
