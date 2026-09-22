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

A freshly scaffolded repository (no objects yet) is a valid generate target. Docs and exports write empty artifacts. Snippet conversion requires the YAML templates from the templates phase and fails if a core or enabled-platform template is missing. Snippet prefixes are `tide-threat`, `tide-objective`, `tide-rule`, and `tide-<platform>` for enabled platforms, with `scope: yaml` and tabstops on empty values.

## generate templates

`opentide generate templates` walks Pydantic `model_fields` (not JSON Schema `$defs`). Output is line-oriented YAML:

- Uncommented keys are required `FieldInfo` on that model (aliases honoured: `att&ck`, `schema`).
- Optional fields are the same YAML with `#` hugging each key (`#references:` / `  #public:`). Nested optionals inside that block are not commented again. Spacer blank lines stay blank (they are not turned into a lone `#`). Uncomment a block and it is valid YAML.
- Placeholders are typed: empty strings, `YYYY-MM-DD`, multiline `|` + `...`, `https://`, `3`, `false`. There are no YAML `null` tokens.
- Vocabulary fields are empty scalars (no enum dump).
- `DetectionRule.file` and other `Path` / hidden fields are omitted.
- Rule `configurations` is a live key whose platform slots (`#sentinel:`, `#splunk:`, …) are commented stubs including nested `query: |`. It is never `configurations: {}`.

JSON Schema generation (`generate schemas`) stays a separate pipeline. VS Code snippets copy the YAML templates and add tabstops; they do not re-walk models.

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
  - `Objective metadata` (priority is the author string — not looked up in `criticality::1.0`), `Signals`, `Signal MDR coverage` (rule backlinks), `Coverage`, `Related objects`
- **Threats:**
  - `Criticality`, `Terrain`, `Threat Assessment`, `Actors`, `CVE` (Vulnerability-Lookup links; optional API enrichment), `ATT&CK Techniques` (when present), `Chaining`, `Chaining details`, `Coverage`, `Related objects`

Metadata is a Field/Value table. Folder index tables add Status/Severity (rules), Priority (objectives), or Criticality (threats).

Internal wiki links are relative to the current folder (`../objectives/…`, `./slug.md` on indexes). Signals are not separate pages — they link to the parent objective heading.

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

- `github` / `generic` write lowercase `docs/{rules,objectives,threats}/<slug>.md`. `[gitlab] uuid_permalinks` does not apply.
- `gitlab` keeps UUID filenames when `[gitlab] uuid_permalinks = true`.
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

- `folder_index_pages`: write `README.md` index pages for `rules`/`objectives`/`threats` and root.
- `index.relation_counts`: include relation counts (or object counts on root index table).
- `index.icons`: prefix section/object labels with emoji markers.

CVE sections on threat pages are controlled by the same file:

```toml
[cve]
base_url = "https://vulnerability.circl.lu"
default_db_link = "https://vulnerability.circl.lu/vuln/"
retrieve_details = true  # fetch title, published date, severity, aliases
proxy = false
```

Identifiers always link to Vulnerability-Lookup (`/vuln/{id}`). CVE, GHSA, and GCVE identifiers are accepted. GNA 0 GCVE ids map to the reserved CVE form (`GCVE-0-2024-3094` → `CVE-2024-3094`) for both API lookup and page links. Legacy NVD `default_db_link` values from older configs are remapped to CIRCL. Set `retrieve_details = false` to emit links only (no API calls).

## generate exports

```bash
opentide generate exports              # all export targets
opentide generate exports navigator
opentide generate exports objects
opentide generate exports revisions
```

`generate exports objects` writes `.opentide/exports/objects.export.json`. Threat `actors` are objects whose `name` is a scoped vocabulary ID (`att&ck::G0006`); the export enriches those names to display names.

## generate inflight

Write preview shards for changed objects, or remove shards superseded by committed objects:

```bash
opentide generate inflight
opentide generate inflight prune
```

The pipelines from `opentide setup ci` run this on every pull request and commit only `.opentide/inflight/` to the default branch, from a worktree of that branch, never the pull request itself.

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
