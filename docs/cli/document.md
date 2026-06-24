---
title: opentide document
description: Generate markdown documentation for rules, objectives, threats, and catalogue indexes.
---

# opentide document

Generate markdown documentation for detection objects.

```bash
opentide document                           # all scopes, then index
opentide document rules
opentide document objectives
opentide document threats
opentide document index
opentide document --output docs --flavor github
```

## Subcommands

| Subcommand | Output |
|------------|--------|
| *(default)* | Rules, objectives, threats, then index pages |
| `rules` | Rule pages under configured rules docs folder |
| `objectives` | Objective pages (signals as `##` sections) |
| `threats` | Threat pages |
| `index` | Folder index / cover pages and root index |

## Options

| Flag | Purpose |
|------|---------|
| `--output` | Output directory (default from `documentation.toml`) |
| `--flavor` | Markdown dialect (overrides auto-detection) |

## Flavors

| `--flavor` | Target |
|------------|--------|
| `github` | GitHub README / GFM |
| `gitlab` | GitLab wiki (`json:table`, YAML frontmatter with UUID permalinks) |
| `azure-devops` | Azure DevOps wiki (`::: mermaid`, `[[_TOC_]]`) |
| `generic` | Portable GFM (local default) |

CI auto-detects flavor from `GITHUB_ACTIONS`, GitLab `CI`, or Azure `TF_BUILD`. `--flavor` always wins.

## Mermaid rendering notes

- **GitHub** — standard ` ```mermaid ` fences; supports `flowchart` and `mindmap`.
- **GitLab** — Mermaid 11.x in recent releases; `json:table` for searchable indexes.
- **Azure DevOps** — uses `::: mermaid` fences; formatter normalises `flowchart`→`graph` and long arrows.

## Configuration

Client `.opentide/configurations/documentation.toml`:

- `folder_index_pages` — per-folder index pages
- `[flavor] default` — local default flavor
- `[gitlab] uuid_permalinks` — UUID filenames + YAML frontmatter

Paths in `global.toml`: `docs_folder`, `rules_docs_folder`, `objectives_docs_folder`, `threats_docs_folder`.

## Programmatic API

```python
from opentide.documentation import render_rule, write_all

md = render_rule(rule)
write_all(include_index=True, output="docs", flavor="github")
```

See [SDK documentation API](../sdk/documentation.md).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/document.py`
