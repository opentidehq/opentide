---
title: Migrating to Workspace
description: The entry points removed with the Python implementation — Opentide.initialise() and its registry, run_validation and ValidationScope, the documentation writers, and opentide's internal modules — and their opentide.Workspace equivalents.
---

# Migrating to Workspace

`opentide.Workspace` replaced the entry points the Python SDK documented before it. They warned (`DeprecationWarning`) for a release cycle, and are now removed, with the Python implementation of the command line they ran on ([#841](https://github.com/opentidehq/opentide/issues/841)): there are no shims. Code that still imports one fails with `ModuleNotFoundError` or `AttributeError`.

| Removed | Use |
|---------|-----|
| `from opentide import Opentide`; `Opentide.initialise()` | `ws = Workspace.open(".")` |
| `Opentide.Rules`, `Opentide.Objectives`, `Opentide.Threats` | `ws.rules()`, `ws.objectives()`, `ws.threats()`: the catalogue's rows |
| `Opentide.Index`, the catalogue and coverage helpers | `ws.info()`, `ws.catalog()`, `ws.coverage("T1059")` |
| `Opentide.Platforms` | `ws.tenants(platform)` and `Connection.open(tenant).capabilities` ([tenant operations](./workspace.md#tenant-operations)) |
| `run_validation(scope=ValidationScope.full())` (`opentide.validation`) | `ws.validate()` |
| `ValidationScope.narrow(files=..., uuids=..., types=...)` | `ws.validate(files=[...], uuids=[...], types=[...])` |
| `report.ok`, `report.errors`, `report.warnings` | `not validation.failed`, `validation.report["issues"]`, `validation.report["warnings"]` |
| `rule.validate()`, `opentide.models.delegation.validate(rule)` | `ws.validate(uuids=[uuid])` |
| `rule.validate_query(platform)` | `await Connection.open(tenant).validate_query(...)`; offline, `opentide.analysis.check_query` ([Query checks](./validation.md)) |
| `rule.run_query(platform, ...)`, `opentide.query.run_query` | `await Connection.open(tenant).query(...)` |
| `rule.deploy(platform, dry_run=True)` | `ws.deploy_plan(strategies=["PREVIEW"], uuids=[uuid], platform=platform)` |
| `rule.deploy(platform)` | `ws.run_json(["deploy", "--uuid", uuid, "--platform", platform, "--strategy", "RELEASE"])` |
| `write_all()`, `write_rules()`, `write_objectives()`, `write_threats()`, `opentide.documentation.run()` | `ws.run_json(["generate", "docs"])` (or `["generate", "docs", "rules"]`, ...) |
| `render_rule`, `render_objective`, `render_threat`, `rule.document()` | `ws.run_json(["generate", "docs", "rules"])`, which writes each object's page |
| A command's service function (`opentide.cli.services.*`) | `ws.run_json([...])`: the command's `--json` document |
| `opentide.models.TideModel`, `TideField`, `TideRegistry`, the result models (`ValidationResult`, `DeploymentResult`), `opentide.models.results`, `opentide.models.configuration` and the other Pydantic modules | The Rust classes in [`opentide.models`](./models.md) for the Tide objects; the documents `Workspace` returns for the rest |
| `opentide.analysis.check_queries`, the catalog helpers | `ws.validate()` (its `queries` check) or `ws.lint()`; `opentide.analysis.check_query` checks one query |

What does not change: the [models](./models.md) (`from opentide.models import DetectionRule`, the Rust classes), the [platform plugins](./platforms.md#platform-plugins) (`opentide.plugins`), and the command line.

Every other module of the package was internal, undocumented, and is removed too: `opentide.cli`, `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.generation`, `opentide.documentation`, `opentide.export`, `opentide.ci`, `opentide.sharing`, `opentide.query`, `opentide.mcp_server`, `opentide.vocabulary`, `opentide.schemas`. A plugin that uses only `opentide.plugins` keeps working.

## Validate

The workspace is a value you open, and the report is `validate --json`'s:

```python
from opentide import Workspace

ws = Workspace.open(".")
validation = ws.validate()
print(not validation.failed, len(validation.report["issues"]))
```

The checks, their codes and their messages are the command line's.

## List and look up objects

Each object is a row of the catalogue, with its path, techniques and platforms already resolved:

```python
from opentide import Workspace

ws = Workspace.open(".")
names = sorted(rule["name"] for rule in ws.rules())
by_uuid = {rule["uuid"]: rule for rule in ws.rules()}
```

## Write the documentation

The command line writes it, as `opentide generate docs` does:

```python
from opentide import Workspace

ws = Workspace.open(".")
result = ws.run_json(["generate", "docs", "--output", "docs"])
print(result["ok"])
```
