# Fumadocs integration

This folder contains scaffolding for the **future OpenTide docs website** (separate repository). Content lives in the parent `docs/` directory.

## Site repository setup

1. Create a Next.js app with Fumadocs UI and Fumadocs MDX.
2. Copy `source.config.ts.example` → `source.config.ts` in the site repo.
3. Point `defineDocs({ dir: … })` at this `docs/` folder:
   - **Git submodule** — `git submodule add … opentide-docs-content`
   - **Monorepo path** — symlink or workspace reference
   - **CI sync** — checkout opentide and copy `docs/` before build

## Four sidebar tabs

Root tabs are folders with `"root": true` in `meta.json`:

| Tab | Folder | Icon |
|-----|--------|------|
| Usage | `usage/` | BookOpen |
| CLI | `cli/` | Terminal |
| MCP | `mcp/` | Bot |
| SDK | `sdk/` | Code |

Fumadocs renders root folders as sidebar tabs (v14+). See [Fumadocs sidebar tabs](https://fumadocs.dev/blog/v14).

## Content format

- Pages: Markdown with YAML frontmatter (`title`, `description`).
- Navigation: `meta.json` per folder.
- Root nav: `docs/meta.json`.

Run validation before publishing:

```bash
scripts/validate-docs.sh
```

## Suggested site layout

```
opentide-docs/                 # future website repo
├── app/
│   └── docs/
│       └── [[...slug]]/page.tsx
├── content/                   # optional: copy or submodule from opentide/docs
├── source.config.ts
├── lib/source.ts
└── package.json
```

## Agent maintenance

Documentation changes in `opentide` should follow [`.agents/skills/docs-maintenance/SKILL.md`](../../.agents/skills/docs-maintenance/SKILL.md).

When CLI, MCP, or public API changes ship, update the corresponding tab in the same PR.
