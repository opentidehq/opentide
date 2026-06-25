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

## Write all pages

```python
from opentide.documentation import write_all, write_rules, write_threats

write_all(include_index=True, output="docs", flavor="github")
write_rules()
```

## CLI entry

```python
from opentide.documentation.cli import run

run(scope="rules", output="docs", flavor="github")
```

## Context and flavors

```python
from opentide.documentation import DocumentationContext, DocumentFlavor
from opentide.documentation.config import load_settings

settings = load_settings(output="docs", flavor="gitlab")
```

Flavors: `github`, `gitlab`, `azure-devops`, `generic`.

Formatters live in `opentide.documentation.format.*`.

## Configuration

Loaded from client `.opentide/configurations/documentation.toml` and bundled defaults.

See [CLI generate](../cli/generate.md) for flavor-specific Mermaid behaviour.

## Public exports

From `opentide.documentation`:

- `render_rule`, `render_objective`, `render_threat`
- `write_rules`, `write_objectives`, `write_threats`, `write_all`
- `DocumentationContext`, `DocumentFlavor`, `run`

## Source

`src/opentide/documentation/api.py`, `src/opentide/documentation/__init__.py`
