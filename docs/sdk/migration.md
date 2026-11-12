---
title: Migrating to Workspace
description: Move SDK code from Opentide.initialise(), run_validation and ValidationScope, and the documentation writers to opentide.Workspace before 0.25 removes them.
---

# Migrating to Workspace

`opentide.Workspace` replaces the entry points the Python SDK documented before it. They keep working through the 0.24 releases and warn (`DeprecationWarning`) when your code calls them; 0.25 removes them. opentide's own command line and MCP server still run on them and never warn.

| Before | Now |
|--------|-----|
| `from opentide import Opentide`; `Opentide.initialise()` | `ws = Workspace.open(".")` |
| `Opentide.Rules`, `Opentide.Objectives`, `Opentide.Threats` | `ws.rules()`, `ws.objectives()`, `ws.threats()`: the catalogue's rows |
| `Opentide.Index`, the catalogue and coverage helpers | `ws.info()`, `ws.catalog()`, `ws.coverage("T1059")` |
| `run_validation(scope=ValidationScope.full())` | `ws.validate()` |
| `ValidationScope.narrow(files=..., uuids=..., types=...)` | `ws.validate(files=[...], uuids=[...], types=[...])` |
| `report.ok`, `report.errors`, `report.warnings` | `not validation.failed`, `validation.report["issues"]`, `validation.report["warnings"]` |
| `rule.deploy(platform, dry_run=True)` | `ws.deploy_plan(strategies=["PREVIEW"], uuids=[uuid], platform=platform)` |
| `rule.deploy(platform)` | `ws.run_json(["deploy", "--uuid", uuid, "--platform", platform, "--strategy", "RELEASE"])` |
| `write_all()`, `write_rules()`, `write_objectives()`, `write_threats()`, `opentide.documentation.run()` | `ws.run_json(["generate", "docs"])` (or `["generate", "docs", "rules"]`, ...) |
| A command's service function (`opentide.cli.services.*`) | `ws.run_json([...])`: the command's `--json` document |

What does not change: the [models](./models.md) (`from opentide.models import DetectionRule`, the Rust classes since 0.24), `render_rule`, `render_objective` and `render_threat` ([Documentation API](./documentation.md#render-single-objects)), and the [platform plugins](./platforms.md).

## Validate

Before, the registry validated the workspace the environment named:

```python
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation

report = run_validation(scope=ValidationScope.full())
print(report.ok, len(report.errors))
```

Now the workspace is a value you open, and the report is `validate --json`'s:

```python
from opentide import Workspace

ws = Workspace.open(".")
validation = ws.validate()
print(not validation.failed, len(validation.report["issues"]))
```

The checks, their codes and their messages are the same: both run the command line's `validate`.

## List and look up objects

Before:

```python
from opentide import Opentide

Opentide.initialise()
names = sorted(rule.name for rule in Opentide.Rules.values())
```

Now each object is a row of the catalogue, with its path, techniques and platforms already resolved:

```python
from opentide import Workspace

ws = Workspace.open(".")
names = sorted(rule["name"] for rule in ws.rules())
by_uuid = {rule["uuid"]: rule for rule in ws.rules()}
```

## Write the documentation

Before:

```python
from opentide.documentation import write_all

write_all(include_index=True, output="docs")
```

Now the command line writes it, as `opentide generate docs` does:

```python
from opentide import Workspace

ws = Workspace.open(".")
result = ws.run_json(["generate", "docs", "--output", "docs"])
print(result["ok"])
```

## Find the calls to change

Turn the warnings into errors in your test suite to find every call:

```bash
python -W error::DeprecationWarning -m pytest
```

Each warning names the call and its replacement, for example `Opentide.initialise() is deprecated and will be removed in opentide 0.25: use opentide.Workspace.open()`.
