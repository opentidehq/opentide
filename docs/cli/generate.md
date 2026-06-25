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

## generate docs

The only supported entry point for markdown documentation.

```bash
opentide generate docs
opentide generate docs --rules --threats --objectives
opentide generate docs --output docs --flavor github
opentide generate docs rules
opentide generate docs index
```

| Flag | Purpose |
|------|---------|
| `--output` | Docs output directory |
| `--flavor` | Renderer flavour (for example `github`) |
| `--rules` / `--threats` / `--objectives` | Limit scopes on the default callback |

Subcommands `rules`, `objectives`, `threats`, and `index` accept the same `--output` and `--flavor` flags.

## generate exports

```bash
opentide generate exports              # all export targets
opentide generate exports navigator
opentide generate exports objects
opentide generate exports revisions
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
| `opentide document` | `opentide generate docs` |
| `opentide export …` | `opentide generate exports …` |
| `opentide extract …` | `opentide generate extract …` |

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/generation.py`
