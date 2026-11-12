---
title: SDK installation
description: Install opentide as a library dependency with PEP 561 typing support.
---

# SDK installation

## Base package

```python
# pyproject.toml — pin the current release in CI
dependencies = ["opentide==0.23.0"]
```

```bash
pip install 'opentide==0.23.0'
```

Includes the CLI, all platform adapters with every vendor SDK they call, the MCP server, and core dependencies (`pydantic`, `pyyaml`, `structlog`, `rich`, `dulwich`, `typer`, `mcp`). There are no extras. Start the server with `opentide mcp start`; see [MCP installation](../mcp/installation.md).

## Vendor SDKs

Programmatic live deploy and query validation work for every platform on the base install. The SDKs each platform calls are listed in [Usage: Installation](../usage/installation.md#vendor-sdks).

## Environment

`Workspace.open` takes the workspace's folder. `run_json` and the deprecated registry read the same environment variables as the CLI:

```python
import os
os.environ["OPENTIDE_REPO_ROOT"] = "/path/to/detection-repo"

from opentide import run_json
info = run_json(["info"])
```

## Typing

The wheel includes `opentide/py.typed` and the stubs of the compiled core (`opentide/_native/*.pyi`). `Workspace`'s options are typed with the choices the command line accepts. Import typed models directly:

```python
from opentide.models.rule import DetectionRule
from opentide.models.results import ValidationResult, DeploymentResult
```

## Editable install (development)

```bash
git clone https://github.com/opentidehq/opentide.git
cd opentide
uv sync --group dev
```

Run tests against your detection repo by setting `OPENTIDE_REPO_ROOT` in pytest or application code.
