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
├── platforms/           # Platform plugins
└── loading/             # YAML loaders
```
