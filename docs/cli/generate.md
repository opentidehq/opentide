---
title: opentide generate
description: Framework generation pipeline — schemas, templates, vocabs, snippets, exports, and docs.
---

# opentide generate

Builds framework artifacts from Pydantic models and bundled vocabulary.

```bash
opentide generate                    # full pipeline
opentide generate schemas            # single phase
```

## Phases (execution order)

When run without a subcommand, phases execute in this order:

| Phase | Subcommand | Output |
|-------|------------|--------|
| vocabs | `generate vocabs` | Object vocabulary indexes |
| templates | `generate templates` | `.opentide/templates/*.template.yaml` |
| schemas | `generate schemas` | `.opentide/schemas/*.schema.json`, IDE router |
| snippets | `generate snippets` | VS Code snippets from templates |
| exports | `generate exports` | Export artifacts (navigator layer, etc.) |
| playbook-map | `generate playbook-map` | Playbook mapping export |
| docs | `generate docs` | Internal docs generation (scoped flags) |

## generate docs

```bash
opentide generate docs
opentide generate docs --rules --threats
```

| Flag | Scope |
|------|-------|
| `--rules` | Rules documentation only |
| `--threats` | Threats documentation only |
| `--objectives` | Objectives documentation only |

Distinct from `opentide document`, which writes client wiki pages from loaded objects.

## When to run

- After upgrading the `opentide` package version.
- When `.opentide/schemas/` is missing or stale.
- After vocabulary or model changes in the package (client repos inherit on upgrade).

## Side effects

Schema and template phases reload `IndexManager` and `OpenTide` registry caches.

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/generation.py`
