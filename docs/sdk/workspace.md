---
title: Workspace
description: opentide.Workspace — open a Tide workspace once, then validate and lint it, list its objects, read its catalogue and coverage, plan a deploy, run any command for its JSON document, and query, check and deploy on its tenants with async methods.
---

# Workspace

`opentide.Workspace` is a Tide workspace: its configuration, resolved once, and every object file, read and parsed once into one index. Opening is the expensive step; each method then reads the index, so keep the `Workspace` and call as many methods on it as you need. Every `Workspace` method runs synchronously and releases the GIL while it runs, so threads can share one `Workspace`. The operations on a tenant, which wait on the network, are `async` methods of a [`Connection`](#tenant-operations).

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

A call that cannot run raises `opentide.OpentideError`, whose `code` is stable: `configuration_invalid` or the configuration check's own code (`config_parse`, ...), `io_error`, `usage_invalid_choice` for an option the command line would refuse, `usage_invalid_value` for a value it would refuse, `no_json_document` when `run_json`'s command writes no document (`--version`), and the [tenant operations](#tenant-operations)' codes. Match on the code, not the message; `detail` holds the vendor's own words when a tenant gave a reason. Findings about the workspace are not errors: they are in the report.

```python
from opentide import OpentideError, run_json

try:
    run_json(["--version"])
except OpentideError as error:
    print(error.code)  # no_json_document
```

When the compiled core does not load (a damaged install), the first call raises `opentide.analysis.EngineUnavailableError`; reinstall with `pip install --force-reinstall opentide`.

## Tenant operations

A `Connection` is one tenant's client: it runs a query (`opentide query`), checks a query live (`opentide validate query --live`) and deploys one compiled rule, through the same platform connectors as the command line. `Workspace.tenants(platform)` returns the tenants the workspace configures, in file order, each a `TenantConfig`:

```toml
# .opentide/configurations/platforms/sentinel_one.toml
[[tenants]]
name = "soc"
[tenants.setup]
url = "$S1_URL"
api_token = "$S1_API_TOKEN"
account_id = 42
```

`Connection.open(tenant)` resolves the tenant's `$NAME` credentials (an unset one raises `credential_unset`, naming the variable) and builds its client from that tenant's own settings: TLS, CA bundle, proxy, timeout. It sends nothing. `environment` replaces the process's environment for the credentials, CA bundles and proxies, `proxy` comes before the environment's, and `timeout` is how long, in seconds, the tenant may take to answer a read. `capabilities` says what the platform's connector can do. A tenant can also be configured in code: `TenantConfig("sentinel_one", "soc", {"url": ..., "api_token": "$S1_API_TOKEN"})`.

`query`, `validate_query` and `deploy` are `async`. Each runs on the Rust core's tokio runtime, started on the first operation, without the GIL while the `asyncio` event loop awaits it, so one connection serves many operations at once:

```python
import asyncio

from opentide import Connection, Workspace

ws = Workspace.open(".")
tenant = ws.tenants("sentinel_one")[0]
tenant.name  # "soc"
connection = Connection.open(tenant)
connection.capabilities.live_validation  # True


async def hunt():
    check, found = await asyncio.gather(
        connection.validate_query("EventType = 'Process Creation'"),
        connection.query("EventType = 'Process Creation'", limit=10),
    )
    print(check.errors, found.columns, found.truncated)
    return found.rows


rows = asyncio.run(hunt())
len(rows)  # 2
```

`query` searches the 24 hours before now unless given `start` and `end` (datetimes; a naive one is taken as UTC), returns at most `limit` rows (100 by default) as a `QueryResult` (`columns`, `rows`, `truncated`, `partial`, `warnings`, `vendor_query_id`, `sent`, `language`) and saves nothing on the tenant. `language` is the query's (`kql`, `esql`, `s1ql`; empty takes the platform's first), `index` the Elastic indices, the HarfangLab telemetry source or the CrowdStrike repository, and `timeout` how long, in seconds, an asynchronous search may run. `validate_query` takes the same options and searches for one row over the minute before now; it returns a `LiveCheck` for a query the tenant accepts, whose `errors` are why validation still fails it (Defender's required columns).

`deploy(rule_id, operation, body)` creates, updates, disables or deletes one rule on the tenant, sending `body` (the request `opentide deploy` compiles for this tenant) as its bytes, and returns a `DeployOutcome` with the platform's identifier of the rule. `rule_id` is the rule's identifier on the platform, which a deploy keeps in its deployment state; a deletion sends no body. A whole deploy run, with its plan, deployment state and retirements, is `ws.run_json(["deploy", ...])`.

```python
outcome = asyncio.run(connection.deploy("1900000000000000001", "delete", b""))
outcome.operation  # "delete"
```

Cancelling the task that awaits an operation stops it, and a search it stops waiting for is stopped on the tenant where the API allows it (CrowdStrike). `connection.canceller()` returns a `Canceller` that stops the connection's operations from elsewhere, a signal handler or another thread: the running one, and every later one, raises `interrupted`.

A platform that cannot do an operation raises `operation_unsupported`, never a faked result: CrowdStrike, HarfangLab and Sysdig cannot check a query live, Sysdig runs no queries, and Elastic deploys only through `opentide deploy`. A tenant that refuses a query raises `tenant_refused`, with the vendor's words in `detail`:

```python
from opentide import OpentideError

try:
    asyncio.run(connection.query("EventType = 'Process Creation' | syntax"))
except OpentideError as error:
    print(error.code, error.detail)  # tenant_refused Syntax error at 3
```

The other codes are `tenant_unreachable`, `tenant_timeout`, `query_timed_out`, `authentication_failed`, `tenant_gateway`, `tenant_answer_invalid`, `tenant_setup_invalid`, `credential_unset`, `connector_crashed`, `interrupted` and `runtime_unavailable`; [the Rust SDK](./rust.md#query-check-and-deploy-on-tenants) has the same operations.

## Asynchronous use

The tenant operations are `async`; every other method is synchronous and releases the GIL while it runs. An `asyncio` application that validates a large workspace without blocking its event loop runs the call in a thread, which the released GIL makes cheap: `await asyncio.to_thread(ws.validate)`.

## Stability

The SDK follows the [Rust SDK](./rust.md#stability)'s promise: the documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
