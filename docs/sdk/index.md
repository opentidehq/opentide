---
title: Python SDK
description: Embed opentide in Python — open a Tide workspace, validate and lint it, read its catalogue and coverage, plan a deploy, and run any command for its JSON document.
icon: Code
---

# Python SDK

The `opentide` PyPI package is the SDK as well as the command line. Its entry point is **`opentide.Workspace`**: a Tide workspace, opened once, with everything you do with it as a method. It wraps the [Rust SDK](./rust.md)'s `opentide` crate one to one, compiled into the package, so Python, Rust and the [TypeScript SDK](./typescript.md) run the same code and return the same documents: the command line's `--json` data, with its keys in its order.

```python
from opentide import Workspace, __version__

ws = Workspace.open(".")
validation = ws.validate()
print(__version__, len(ws.rules()), "rules,", validation.summary["objects"], "objects checked")
```

## Public entry points

| Symbol | Purpose |
|--------|---------|
| `opentide.Workspace` | Open a workspace (`open`, `from_files`); `validate`, `lint`, `info`, `rules`, `objectives`, `threats`, `catalog`, `coverage`, `deploy_plan`, `run_json` |
| `opentide.run_json` | Run any `opentide` command in the process and return its `--json` document |
| `opentide.OpentideError` | What a call that cannot run raises, with a stable `code` |
| `opentide.Validation`, `opentide.LintReport`, `opentide.DeployPlan` | What `validate`, `lint` and `deploy_plan` return |
| `opentide.models` | The Tide models: `DetectionRule`, `ThreatVector`, `DetectionObjective`, the platform blocks |
| `opentide.__version__` | The package's version |

`import opentide` loads none of them until you use one: it takes about a millisecond, and 30 ms at most.

## Documentation map

| Page | Topic |
|------|-------|
| [Installation](./installation.md) | Install, vendor SDKs and typing support |
| [Workspace](./workspace.md) | Open, validate, lint, the catalogue, coverage, the deploy plan, `run_json`, errors |
| [Migration](./migration.md) | From `Opentide.initialise()`, `run_validation` and the documentation writers to `Workspace` |
| [Models](./models.md) | The Tide models |
| [Platforms](./platforms.md) | Deployers, validators, plugins |
| [Configuration](./configuration.md) | The configuration accessors |
| [Registry](./registry.md), [Validation](./validation.md), [Documentation API](./documentation.md) | The entry points before `Workspace`, deprecated: removed in 0.25 |
| [Rust SDK](./rust.md) | The `opentide` crate: workspace, validate, catalogue, deploy plan, command line |
| [TypeScript SDK](./typescript.md) | The `@opentide/opentide` npm package |

## Worked example: validate, then plan a deploy

Validate the workspace, stop on an error, and plan what a deploy of the rules in preview would send. Nothing is sent and nothing is written:

```python
from opentide import Workspace

ws = Workspace.open(".")

validation = ws.validate()
for issue in validation.report["issues"]:
    print(f"{issue['path']}:{issue['line']}: {issue['code']}: {issue['message']}")
if validation.failed:
    raise SystemExit(validation.exit_code)

plan = ws.deploy_plan(strategies=["PREVIEW"])
for platform, rules in plan.document["plan"].items():
    print(platform, len(rules), "rules")
print(plan.summary)
```

A real deploy is the command line's: `ws.run_json(["deploy", "--strategy", "RELEASE", "--all"])` runs it in the process and returns its envelope, with [credentials](../usage/configuration.md#credentials) set in the environment.

## Choosing between SDK, CLI, and MCP

Use the SDK to embed the engine in Python; use the [CLI](../cli/index.md) for humans and pipelines; use [MCP](../mcp/index.md) for agents. See [Choosing an interface](../usage/choosing-an-interface.md).

## Type hints

The package ships `py.typed` (PEP 561) and the stubs of its compiled module (`opentide/_native/*.pyi`); `ty` checks the package with no exclusions. The options are typed with the choices the command line accepts (`queries="warn"`, `strategies=["PREVIEW"]`); the documents are `dict[str, Any]`, with the keys of [JSON output](../cli/json-output.md).

## Source layout

```
src/opentide/
├── __init__.py          # Workspace, run_json, __version__ (loaded on first use)
├── sdk.py               # Workspace and run_json, over opentide._native.sdk
├── _native/             # the compiled Rust core and its stubs
├── models/              # the Tide models
├── platforms/           # platform adapters
└── core/registry.py     # Opentide, deprecated
```
