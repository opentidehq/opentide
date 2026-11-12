---
title: Workspace
description: opentide.Workspace — open a Tide workspace once, then validate and lint it, list its objects, read its catalogue and coverage, plan a deploy, and run any command for its JSON document.
---

# Workspace

`opentide.Workspace` is a Tide workspace: its configuration, resolved once, and every object file, read and parsed once into one index. Opening is the expensive step; each method then reads the index, so keep the `Workspace` and call as many methods on it as you need. Every method runs synchronously and releases the GIL while it runs, so threads can share one `Workspace`.

## Open a workspace

`Workspace.open` takes the repository's folder (the one with `.opentide/` and `objects/`), or a folder inside it. `cwd` is the folder paths in findings are shown from; by default, the workspace's own.

```python
from opentide import Workspace

ws = Workspace.open(".")
print(ws.root, ws.info()["counts"])
```

`Workspace.from_files` opens a workspace held in memory, for an editor's buffers or a test: each key is a path relative to the root, each value the file's text. Nothing is read from or written to the disk.

```python
from opentide import Workspace

ws = Workspace.from_files(
    "/ws",
    {
        "objects/rules/example.yaml": (
            "name: Example\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n"
        ),
    },
)
names = [rule["name"] for rule in ws.rules()]
names  # ["Example"]
```

## Validate

`validate` runs every check of `opentide validate` and returns a `Validation`: `checks`, `report` and `summary` as `validate --json` writes them, with `failed`, `warned` and the command's `exit_code`. Each finding of `report["issues"]` and `report["warnings"]` has its `code`, `severity`, `path`, 1-based `line` and `column`, `field_path`, `suggestion` and `fix`.

The options are the command's flags: `check` (one check), `files`, `uuids`, `types`, `strict` and `queries` (`"error"`, `"warn"` or `"off"`).

```python
from opentide import Workspace

ws = Workspace.open(".")
validation = ws.validate(types=["rule"], strict=True)
for finding in validation.report["issues"] + validation.report["warnings"]:
    print(f"{finding['path']}:{finding['line']}: {finding['message']}")
print(validation.summary["objects"], "objects checked;", "failed" if validation.failed else "passed")

uuids = ws.validate(check="uuid-format")
list(uuids.checks)  # ["uuid-format"]
```

## Lint

`lint` runs `opentide lint` (the checks `lint.toml` enables, or those you name) without `--fix`: its `findings` and `summary` are those of `lint --json`, with the `status` (`completed`, `issues` or `failed`), the `message` and the `exit_code`.

```python
from opentide import Workspace

ws = Workspace.open(".")
report = ws.lint(checks=["filenames", "metadata"])
for finding in report.findings:
    print(finding["code"], finding["path"])
print(report.status, report.exit_code)
```

## List the objects

`rules`, `objectives` and `threats` return their rows of the catalogue, in the order the index met them: `uuid`, `type`, `schema`, `name`, `path`, `techniques` (own and inherited), `tactics`, `actors`, `platforms`, and the metadata (`tlp`, `author`, `created`, `modified`).

```python
from opentide import Workspace

ws = Workspace.open(".")
for rule in ws.rules():
    print(rule["uuid"], rule["name"], rule["techniques"]["own"], [p["id"] for p in rule["platforms"]])
print(len(ws.objectives()), "objectives,", len(ws.threats()), "threats")
```

For a rule's full YAML as a typed object, read it with the [models](./models.md): `DetectionRule.model_validate(...)`.

## Read the catalogue and coverage

`info`, `catalog` and `coverage` return the data of `opentide info`, `info catalog` and `info coverage`.

```python
from opentide import Workspace

ws = Workspace.open(".")
info = ws.info()
print(f"{info['counts']['rules']} rules, {info['load_errors']} load errors")
catalogue = ws.catalog()
print(len(catalogue["objects"]), "objects,", len(catalogue["edges"]), "edges")
coverage = ws.coverage("T1059")
print(f"{coverage['count']} rules cover {coverage['technique']}")
```

A tenant in `info()["platforms"]` names the environment variables it reads and whether each is set in this process, never their values.

## Plan a deploy

`deploy_plan` is `opentide deploy --dry-run`: the rules the strategies select, the tenants each reaches and the request bodies a real run would send. Nothing is sent and nothing is written. Without `uuids` or `files` it plans every rule file (`--all`); `platform` plans for one platform, and `keep_deprecated` is `--keep-deprecated` (`True`) or `--drop-deprecated` (`False`).

```python
from opentide import Workspace

ws = Workspace.open(".")
plan = ws.deploy_plan(strategies=["PREVIEW"])
print(plan.ok, plan.document["strategies"], list(plan.document["plan"]))
print(plan.summary)
```

`document` is the `result` of `deploy --dry-run --json`; `summary` its counts; `ok` whether the dry run completed. What would stop a real run (a platform without tenants, an unset variable) is in `document["warnings"]`.

## Run a command

`run_json(argv)` runs one `opentide` command in this process and returns its `--json` document: the envelope (`ok`, `command`, `failure`, and the result's keys) or, for `commands`, the command tree. A command that fails still returns its document, with `ok` false and `failure["code"]`. It reads the process's environment and working directory as the command line does, and writes nothing to the process's streams. `Workspace.run_json` runs it on the workspace (`--repo <root>`).

```python
from opentide import Workspace, run_json

tree = run_json(["commands"])
tree["program"]  # "opentide"

ws = Workspace.open(".")
docs = ws.run_json(["generate", "docs"])
print(docs["ok"], docs["command"])
```

Every command is reachable this way, the deploy itself included (`["deploy", "--strategy", "RELEASE", "--all"]`). The [CLI reference](../cli/index.md) lists them, and [JSON output](../cli/json-output.md) their documents.

## Errors

A call that cannot run raises `opentide.OpentideError`, whose `code` is stable: `configuration_invalid` or the configuration check's own code (`config_parse`, ...), `io_error`, `usage_invalid_choice` for an option the command line would refuse, `no_json_document` when `run_json`'s command writes no document (`--version`). Match on the code, not the message. Findings about the workspace are not errors: they are in the report.

```python
from opentide import OpentideError, run_json

try:
    run_json(["--version"])
except OpentideError as error:
    print(error.code)  # no_json_document
```

When the compiled core does not load (a damaged install), the first call raises `opentide.analysis.EngineUnavailableError`; reinstall with `pip install --force-reinstall opentide`.

## Asynchronous use

Every method is synchronous. In an `asyncio` application, run one in a thread, which the released GIL makes cheap: `await asyncio.to_thread(ws.validate)`. Native `async` methods for the tenant operations (deploy, live query validation, query runs) come with the platform connectors of the Rust core.

## Stability

The SDK follows the [Rust SDK](./rust.md#stability)'s promise: the documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
