---
title: SDK installation
description: Install opentide as a library dependency with platform extras and PEP 561 typing support.
---

# SDK installation

## Base package

```python
# pyproject.toml
dependencies = ["opentide>=0.1"]
```

```bash
pip install opentide
```

Core dependencies: `pydantic>=2`, `pyyaml`, `structlog`, `rich`, `GitPython`, `ruamel.yaml`.

## Platform extras

Add extras for optional platform SDKs (same as CLI):

```toml
dependencies = [
  "opentide[sentinel,splunk]>=0.1",
]
```

See [Usage: Installation](../usage/installation.md) for the full extras table.

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
