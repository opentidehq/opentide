# opentide document

Generate markdown documentation for detection objects under `docs/{Rules,Objectives,Threats}/`.

## Usage

```bash
opentide document                      # full pipeline: objects then index
opentide document --scope rules        # rules only
opentide document --scope objectives   # objectives only
opentide document --scope threats      # threats only
opentide document --scope index        # index pages only
opentide document --output docs        # output directory (default from config)
opentide document --flavor github      # markdown dialect
```

## Scopes

| Scope | Output |
|-------|--------|
| `rules` | `docs/Rules/*.md` |
| `objectives` | `docs/Objectives/*.md` (signals as `##` sections) |
| `threats` | `docs/Threats/*.md` |
| `index` | folder README/cover pages + root index |
| *(none)* | all scopes in order, then index |

## Flavors

| `--flavor` | Target |
|------------|--------|
| `github` | GitHub README / GFM |
| `gitlab` | GitLab wiki (`json:table`, YAML frontmatter when UUID permalinks) |
| `azure-devops` | Azure DevOps wiki (`::: mermaid`, `[[_TOC_]]`) |
| `generic` | portable GFM (default locally) |

CI auto-detects flavor from `GITHUB_ACTIONS`, `CI` (GitLab), or `TF_BUILD` (Azure Pipelines). `--flavor` always wins.

## Platform Mermaid notes

Research (June 2026) on wiki rendering:

- **GitHub** — standard ` ```mermaid ` fences; broad Mermaid support including `flowchart` and `mindmap`.
- **GitLab GLFM** — ` ```mermaid ` fences; Mermaid 11.x in recent releases; `json:table` for searchable indexes.
- **Azure DevOps** — Sprint 274+ accepts standard ` ```mermaid ` fences in addition to `::: mermaid`. Microsoft docs still list syntax limits: prefer `graph` over `flowchart`, avoid `---->` long arrows, and avoid subgraphs in complex diagrams.

OpenTide emits full Mermaid (`flowchart`, `mindmap`) for GitHub, GitLab, and generic. The Azure DevOps formatter applies **minimal** normalisation only (`flowchart`→`graph`, `---->`→`-->`) and uses `::: mermaid` fences.

## Configuration

`configurations/documentation.toml`:

- `folder_index_pages` — write per-folder index pages
- `[flavor] default` — local default flavor
- `[gitlab] uuid_permalinks` — UUID filenames + YAML frontmatter

`configurations/global.toml` paths:

- `docs_folder`, `rules_docs_folder`, `objectives_docs_folder`, `threats_docs_folder`

## Programmatic API

```python
from opentide.documentation import render_rule, write_all

md = render_rule(rule)
write_all(include_index=True, output="docs", flavor="github")
```
