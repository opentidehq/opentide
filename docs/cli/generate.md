---
title: opentide generate
description: Output-first generation pipeline — docs, exports, vocabs, templates, schemas, snippets, and optional platform import.
---

# opentide generate

Builds client-visible outputs first, then framework internals from Pydantic models and bundled vocabulary.

```bash
opentide generate                    # full pipeline (no extract)
opentide generate schemas            # single phase
opentide generate docs --output docs
opentide generate exports navigator
opentide generate inflight
opentide generate inflight prune
opentide generate extract sentinel   # opt-in platform import
```

## Default pipeline order

When run without a subcommand, phases execute in this order:

| Order | Phase | Subcommand | Output |
|-------|-------|------------|--------|
| 1 | docs | `generate docs` | Markdown documentation for rules, objectives, threats |
| 2 | exports | `generate exports` | ATT&CK navigator layer, objects export, revisions export |
| 3 | vocabs | `generate vocabs` | In-memory object vocabulary indexes |
| 4 | templates | `generate templates` | `.opentide/templates/*.template.yaml` |
| 5 | schemas | `generate schemas` | `.opentide/schemas/*.schema.json`, IDE router |
| 6 | snippets | `generate snippets` | VS Code snippets from templates |

`extract` is **not** part of the default run — it calls live platform APIs and writes `Imported/` in the working directory. Use `opentide generate extract` explicitly when importing rules.

A freshly scaffolded repository (no objects yet) is a valid generate target. Docs and exports write empty artifacts, and snippet generation skips templates that have not been produced yet instead of failing.

## generate docs

The only supported entry point for markdown documentation.

```bash
opentide generate docs
opentide generate docs --changed
opentide generate docs --rules --threats --objectives
opentide generate docs --output docs --flavor github
opentide generate docs rules
opentide generate docs index
```

| Flag | Purpose |
|------|---------|
| `--output` | Docs output directory |
| `--flavor` | Renderer flavour (for example `github`) |
| `--changed` | Generate only docs for changed object YAMLs (from git merge-base diff + untracked files), expanded with upstream referrer closure, remove pages for deleted objects, then rewrite affected indexes |
| `--rules` / `--threats` / `--objectives` | Limit scopes on the default callback |

`--changed` is only supported on full `opentide generate docs` runs and cannot be combined with `--rules`, `--threats`, or `--objectives`.

Subcommands `rules`, `objectives`, `threats`, and `index` accept the same `--output` and `--flavor` flags.

### Rendered sections by object type

`generate docs` now renders shared metadata and references sections for all object families, plus richer object-specific sections:

- **Shared (rules, objectives, threats):**
  - `Metadata` (UUID, schema, version, created/modified, TLP, optional author/contributors/organisation)
  - `References` (`Public`, `Internal`, `Reports` buckets when present)
- **Rules:**
  - `Status`, `ATT&CK Techniques`, `Detection model` (relative backlink), `Response`, `Platform configurations`, `Coverage`, `Related objects`
- **Objectives:**
  - `Objective metadata`, `Signals`, `Signal MDR coverage` (rule backlinks), `Coverage`, `Related objects`
- **Threats:**
  - `Criticality`, `Terrain`, `Threat Assessment`, `Actors`, `ATT&CK Techniques` (when present), `Chaining`, `Chaining details`, `Coverage`, `Related objects`

Metadata is a Field/Value table. Folder index tables add Status/Severity (rules), Priority (objectives), or Criticality (threats).

Internal wiki links are relative to the current folder (`../Objectives/…`, `./slug.md` on indexes). Signals are not separate pages — they link to the parent objective heading.

### Mermaid behavior and relations direction

Threat chaining and coverage are rendered with Mermaid across flavors:

- **Coverage diagram:** 2-hop threat → objective → signal → rule flowchart with typed node shapes (hexagon / stadium / circle / rectangle) and family subgraphs. The section is titled `Coverage` only when this graph is present; a generic relations flowchart uses a `Relations` heading instead.
- **Chaining diagram:** inbound + outbound threat-to-threat flow, with kill-chain subgraphs when present and bidirectional arrows for synergistic links.
- **Related objects table:** clickable backlinks (GitHub does not honor Mermaid `click`). `relations_direction` still controls which rows appear (`upstream`, `downstream`, or `both`).

```toml
[diagrams]
relations_direction = "both" # upstream | downstream | both
```

Flavor notes:

- `github` / `gitlab` / `generic` render flowchart-style relations and chaining.
- `azure-devops` downgrades to `graph` syntax and disables subgraphs for compatibility.

### Index enrichment options

Folder and root index pages can be enriched from `.opentide/configurations/documentation.toml`:

```toml
folder_index_pages = true

[index]
relation_counts = true
icons = false
```

- `folder_index_pages`: write `README.md` index pages for Rules/Objectives/Threats and root.
- `index.relation_counts`: include relation counts (or object counts on root index table).
- `index.icons`: prefix section/object labels with emoji markers.

## generate exports

```bash
opentide generate exports              # all export targets
opentide generate exports navigator
opentide generate exports objects
opentide generate exports revisions
```

## generate inflight

Write preview shards for changed objects, or remove shards superseded by committed objects:

```bash
opentide generate inflight
opentide generate inflight prune
```

## generate extract

Import detection rules from external platforms (credential-heavy, experimental for Defender):

```bash
opentide generate extract sentinel
opentide generate extract defender
```

Configure tenant credentials under `.opentide/configurations/platforms/` before running.

## When to run

- After upgrading the `opentide` package version.
- When `.opentide/schemas/` is missing or stale.
- After vocabulary or model changes in the package (client repos inherit on upgrade).

## Side effects

Schema and template phases reload `IndexManager` and `OpenTide` registry caches.

## Deprecated shims

| Legacy command | Replacement |
|----------------|-------------|
| `opentide generate docs` | `opentide generate docs` |
| `opentide generate exports …` | `opentide generate exports …` |
| `opentide generate extract …` | `opentide generate extract …` |

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/generation.py`
