---
title: Python SDK
description: Embed OpenTide in Python applications — registry lifecycle, validation, documentation, and platform plugins.
icon: Code
---

# Python SDK

The `opentide` PyPI package exposes a typed programmatic API centred on the **`OpenTide`** registry singleton.

```python
from opentide import OpenTide, __version__

OpenTide.initialise()
print(__version__, len(OpenTide.Rules))
```

## Public entry points

| Symbol | Module | Purpose |
|--------|--------|---------|
| `OpenTide` | `opentide.core.registry` | Registry singleton |
| `__version__` | `opentide._version` | Package version string |

Additional APIs are importable from subpackages (`opentide.validation`, `opentide.documentation`, `opentide.models`) but the registry is the primary integration surface.

## Documentation map

| Page | Topic |
|------|-------|
| [Installation](./installation.md) | Extras and typing support |
| [Registry](./registry.md) | Lifecycle, accessors, lookup |
| [Validation](./validation.md) | `run_validation`, scopes, reports |
| [Documentation API](./documentation.md) | Render and write markdown pages |
| [Models](./models.md) | Pydantic object types |
| [Platforms](./platforms.md) | Deployers, validators, plugins |

## Worked example: validate then deploy

A complete pipeline — initialise, validate the whole repo, and dry-run deploy the rules that pass:

```python
from opentide import OpenTide
from opentide.validation.session import run_validation
from opentide.validation.scope import ValidationScope
from opentide.core.errors import Errors

OpenTide.initialise()

# 1. Validate the entire workspace
report = run_validation(scope=ValidationScope.full())
if not report.ok:
    for issue in report.errors:
        print("ERROR:", issue.to_legacy_string())
    raise SystemExit(1)

# 2. Deploy production rules to Sentinel (dry-run first)
platform = "sentinel"
if not OpenTide.Platforms[platform].can_deploy:
    raise SystemExit(f"{platform} has no deployer configured")

for uuid, rule in OpenTide.Rules.items():
    if rule.status != "PRODUCTION":
        continue
    try:
        result = rule.deploy(platform, dry_run=True)
        print(uuid, result.dry_run, result.message)
    except Errors.TideDeploymentErrors as exc:
        print("DEPLOY FAILED", uuid, exc)
```

Set `dry_run=False` and provide [credentials](../usage/configuration.md#credentials) for a real deploy. See [Validation](./validation.md) and [Models → delegation](./models.md#delegation-methods).

## Choosing between SDK, CLI, and MCP

Use the SDK to embed the engine in Python; use the [CLI](../cli/index.md) for humans and pipelines; use [MCP](../mcp/index.md) for agents. See [Choosing an interface](../usage/choosing-an-interface.md).

## CLI and MCP

The CLI and MCP server are thin wrappers around the same engine modules documented here.

| Surface | Entry |
|---------|-------|
| CLI | `opentide.cli` |
| MCP | `opentide.mcp_server` |

## Type hints

The package ships `py.typed` (PEP 561). Use ty or mypy in consuming projects.

## Source layout

```
src/opentide/
├── __init__.py          # OpenTide, __version__
├── core/registry.py     # OpenTideRegistry
├── models/              # Pydantic models
├── validation/          # Pipeline and reports
├── documentation/       # Markdown rendering
├── platforms/           # Platform adapters
└── loading/             # YAML loaders
```
