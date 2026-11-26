---
title: SDK installation
description: Install opentide as a library dependency with PEP 561 typing support.
---

# SDK installation

## Base package

```python
# pyproject.toml — pin the current release in CI
dependencies = ["opentide==1.1.0"]
```

```bash
pip install opentide              # the latest release
pip install 'opentide==1.1.0'     # or pin it
```

This SDK (`opentide.Workspace` and the rest of these pages) is new in 1.0: the 0.x releases have none of it ([Migrating to Workspace](./migration.md)). See [Installation](../usage/installation.md) for uv, pipx, crates.io, npm and the binaries.

Includes the CLI, the thirteen platform connectors, the MCP server and the SDK, all compiled into one Rust core inside the wheel; it has no Python dependency. The `plugins` extra installs `pydantic`, which the [plugin API](./platforms.md#platform-plugins) needs: `pip install 'opentide[plugins]'`; nothing else asks for an extra. Start the MCP server with `opentide mcp start`; see [MCP installation](../mcp/installation.md).

## Platforms

Live deploy, queries and query checks work for every platform on the base install: each platform's connector speaks its vendor's REST API itself, with no vendor SDK.

## Environment

`Workspace.open` takes the workspace's folder. `run_json` reads the same environment variables as the CLI:

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
from opentide.models import ValidationError
```

## Editable install (development)

```bash
git clone https://github.com/opentidehq/opentide.git
cd opentide
uv sync --group dev
```

Run tests against your detection repo by setting `OPENTIDE_REPO_ROOT` in pytest or application code.
