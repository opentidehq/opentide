---
name: opentide-docs-maintenance
description: >-
  Maintain OpenTide documentation in docs/ — Fumadocs structure, frontmatter,
  meta.json navigation, and keeping CLI/MCP/SDK pages in sync with code.
---

# OpenTide documentation maintenance

Use this skill when adding features, changing CLI/MCP/SDK surface area, or authoring pages under `docs/`.

## Doc structure (four tabs)

| Tab | Path | Update when |
|-----|------|-------------|
| Usage | `docs/usage/` | Setup flows, workflows, concepts, migration |
| CLI | `docs/cli/` | Typer commands, flags, behaviour |
| MCP | `docs/mcp/` | Tools, resources, config templates |
| SDK | `docs/sdk/` | Public Python API, registry, models |

Internal maintainer docs: `docs/internal/` (excluded from public site root).

Authoring conventions: [`docs/README.md`](../../docs/README.md).

## Page template

Every new page:

```markdown
---
title: Human title
description: One sentence for cards and search
---

# Human title

First paragraph explains purpose in plain language.
```

Optional Fumadocs fields: `icon`, `full`.

## Navigation

Add the page slug to the folder's `meta.json` `pages` array. Root tabs use `"root": true`.

```json
{
  "pages": ["index", "---Section---", "new-page"]
}
```

## Code change checklist

When modifying source, update docs in the **same PR**:

| Source file | Doc target |
|-------------|------------|
| `src/opentide/cli/__init__.py` | `docs/cli/*.md` |
| `src/opentide/cli/setup_app.py` | `docs/cli/setup.md`, `docs/usage/repository-setup.md` |
| `src/opentide/mcp_server/server.py` | `docs/mcp/tools.md`, `docs/mcp/resources.md` |
| `src/opentide/mcp_server/tools.py` | `docs/mcp/tools.md` |
| `src/opentide/core/registry.py` | `docs/sdk/registry.md` |
| `src/opentide/__init__.py` | `docs/sdk/index.md` |
| `src/opentide/cli/enums.py` (platforms) | `docs/usage/concepts/platforms.md` |
| `src/opentide/data/setup/skills/` | `docs/usage/workflows/agentic-setup.md` |

## Verify CLI accuracy

Extract live help when documenting flags:

```bash
uv run opentide --help
uv run opentide <command> --help
```

Do not document flags that do not exist (e.g. legacy `--scope` on `document` — use subcommands).

## Validation

```bash
scripts/validate-docs.sh
```

Fixes: missing frontmatter, broken internal links, orphan pages not listed in meta.json.

### Golden command runner

`scripts/validate-docs.sh` is structural. Command accuracy is enforced by
`tests/test_docs/test_docs_commands_golden.py`, which reads every `opentide …`
invocation out of the `bash` / `sh` / `shell` / `console` fences in `docs/`:

```bash
uv run pytest tests/test_docs/test_docs_commands_golden.py -q
```

| Gate | What fails |
|------|------------|
| Resolution | A documented subcommand, flag, or positional count the live Typer tree does not have |
| Execution | A read-only sample (`validate`, `lint`, `info`, `generate`) that raises or does not emit one JSON envelope |
| Output samples | A `text`/`json` fence tagged `output-of="opentide …"` whose lines the command no longer prints, or whose `exit=N` the command or its section contradicts |

Failures name the page and line, so fix the page — or the CLI — rather than
loosening the test. Extraction lives in `tests/docs_commands.py`; add a page
and it is picked up automatically.

Writing a sample means committing to it. Capture real output from a scaffolded
repo and tag the fence with the command that printed it, e.g.
`` ```text output-of="opentide deploy metadata --platform splunk" exit=2 ``.
The command must also appear in a shell fence on the page; see
[`docs/README.md`](../../../docs/README.md#output-samples) for the matching rules.

## Platform capability rule

Seven platforms deploy; five validate queries. CrowdStrike and HarfangLab: **`supported: false`** for query validation — document this consistently in Usage, CLI, MCP, and SDK pages.

## Cross-linking

- Usage → CLI/MCP/SDK for "technical reference"
- CLI/MCP/SDK → Usage for "getting started"
- Relative paths only; no hardcoded `github.com/.../blob/` for in-repo pages

## Fumadocs site repo

**Build and deploy:** [OpenTideHQ/website](https://github.com/OpenTideHQ/website). This repo ships content under `docs/` only.

After CLI/Usage changes, the website still needs `pnpm sync:content` so `content/docs/` picks up new pages (`lint`, `migrate`) and nav. Landing hero copy in `components/landing/hero-terminal.tsx` is independent of this tree — keep it aligned with the first-user sequence (`setup` → `generate` → `validate` → `deploy --dry-run`).

Notes: [`docs/fumadocs/`](../../docs/fumadocs/).
