# Fumadocs integration

Public docs are built and deployed by **[OpenTideHQ/website](https://github.com/OpenTideHQ/website)** at [opentide.org/docs](https://opentide.org/docs). This folder is authoring notes for that site. Content lives in the parent `docs/` directory.

The website copies this tree with `pnpm sync:content` into `content/docs/{usage,cli,mcp,sdk}` and commits the snapshot so GitHub Pages can build without private-repo access. A weekly Actions job bumps the `vendor/opentide` submodule; the committed snapshot still needs an explicit sync.

When this repo adds CLI pages (`lint`, `migrate`) or changes the first-user command sequence, the website snapshot can lag until someone runs `pnpm sync:content`. Keep Usage/CLI examples accurate here — that is the source of truth.

## Site repository setup

The live site already exists. For a local preview with sibling clones:

```bash
OPENTIDE_DOCS_PATH=../opentide/docs SPECIFICATIONS_PATH=../specifications pnpm dev
```

Alternatively use the website's `vendor/opentide` submodule.

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

## Website layout (OpenTideHQ/website)

```
website/
├── app/docs/[[...slug]]/page.tsx
├── content/docs/              # committed snapshot from this docs/ tree
├── vendor/opentide            # submodule used by pnpm sync:content
└── source.config.ts
```

Landing copy (hero terminal) is **not** generated from this tree. If the first-user command sequence changes (`setup` → `generate` → `validate` → `deploy --dry-run`), update `components/landing/hero-terminal.tsx` in the website repo in the same docs cycle. The current hero skips `generate`, which is the command that failed for empty and populated repos in #153 and #172.

## Agent maintenance

Documentation changes in `opentide` should follow [`.agents/skills/docs-maintenance/SKILL.md`](../../.agents/skills/docs-maintenance/SKILL.md).

When CLI, MCP, or public API changes ship, update the corresponding tab in the same PR.
