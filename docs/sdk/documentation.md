---
title: Documentation API
description: Render and publish markdown documentation for rules, objectives, and threats.
---

# Documentation API

Programmatic access to the same renderer used by `opentide generate docs`.

## Render single objects

```python
from opentide import OpenTide
from opentide.documentation import render_rule, render_objective, render_threat
from opentide.documentation.types import DocumentFlavor

OpenTide.initialise()
rule = OpenTide.Rules[uuid]

md = render_rule(rule)
md_github = render_rule(rule, flavor=DocumentFlavor.github)
```

Rendered pages include shared `Metadata` and `References` sections, plus object-specific sections:

- `render_rule`: status/techniques, detection model links, response metadata/procedures, platform query configurations, relations diagram
- `render_objective`: objective metadata, signal details, signal-to-rule MDR coverage, relations diagram
- `render_threat`: criticality/terrain/assessment/actors, ATT&CK techniques (when present), chaining + chaining details, relations diagram

## Write all pages

```python
from opentide.documentation import write_all, write_rules, write_threats

write_all(include_index=True, output="docs", flavor="github")
write_rules()
```

`include_index=True` writes folder and root index pages in addition to object pages.

## CLI entry

```python
from opentide.documentation.cli import run

run(scope="rules", output="docs", flavor="github")
run(output="docs", flavor="github", changed=True)
```

With `changed=True`, `run()` computes changed object YAMLs from the git merge-base diff (plus untracked files), expands upstream referrer closure, removes pages for deleted objects, renders only targeted object pages, and rewrites indexes.

`changed=True` is only supported for full docs generation (`scope=None`) and cannot be combined with scoped CLI filters such as `--rules`, `--threats`, or `--objectives`.

## Context and flavors

```python
from opentide.documentation import DocumentationContext, DocumentFlavor
from opentide.documentation.config import load_settings

settings = load_settings(output="docs", flavor="gitlab")
```

Flavors: `github`, `gitlab`, `azure-devops`, `generic`.

Formatters live in `opentide.documentation.format.*`.

### Mermaid behavior and relation direction

Relations and chaining diagrams are always rendered through flavor-aware Mermaid formatters:

- `github` / `gitlab` / `generic`: flowchart output, with relation subgraphs when available.
- `azure-devops`: graph-compatible output with subgraphs disabled.

`relations_direction` is loaded from documentation settings (`upstream`, `downstream`, or `both`) and applied to relations diagrams for rules, objectives, and threats.

### Index enrichment controls

`DocumentationContext` carries index options loaded by `load_settings()`:

- `folder_index_pages`
- `index_relation_counts`
- `index_icons`

These options control whether index pages are written and whether tables include relation counts/icons.

## Configuration

Loaded from client `.opentide/configurations/documentation.toml` and bundled defaults.

Key settings:

```toml
folder_index_pages = true

[diagrams]
relations_direction = "both"

[index]
relation_counts = true
icons = false
```

See [CLI generate](../cli/generate.md) for flavor-specific Mermaid behaviour.

## Public exports

From `opentide.documentation`:

- `render_rule`, `render_objective`, `render_threat`
- `write_rules`, `write_objectives`, `write_threats`, `write_all`
- `DocumentationContext`, `DocumentFlavor`, `run`

## Source

`src/opentide/documentation/api.py`, `src/opentide/documentation/__init__.py`
