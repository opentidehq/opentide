---
title: SDK installation
description: Install opentide as a library dependency with PEP 561 typing support.
---

# SDK installation

## Base package

```python
# pyproject.toml — pin the current patch in CI
dependencies = ["opentide==0.1.1"]
```

```bash
pip install 'opentide==0.1.1'
```

Includes the CLI, MCP server (`opentide-mcp`), all platform adapters, and core dependencies (`pydantic`, `pyyaml`, `structlog`, `rich`, `dulwich`, `typer`, `mcp`, `fastmcp`, etc.).

## Live deploy SDKs

For programmatic live deploy to Splunk or Carbon Black, install vendor SDKs alongside opentide — see [Usage: Installation](../usage/installation.md).

## Environment

Library code respects the same environment variables as the CLI:

```python
import os
os.environ["OPENTIDE_REPO_ROOT"] = "/path/to/detection-repo"

from opentide import OpenTide
OpenTide.initialise()
```

## Typing

The wheel includes `opentide/py.typed`. Import typed models directly:

```python
from opentide.models.rule import DetectionRule
from opentide.models.results import ValidationResult, DeploymentResult
```

## Editable install (development)

```bash
git clone https://github.com/OpenTideHQ/opentide.git
cd opentide
uv sync --group dev
```

Run tests against your detection repo by setting `OPENTIDE_REPO_ROOT` in pytest or application code.
