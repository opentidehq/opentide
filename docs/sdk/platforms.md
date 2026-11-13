---
title: Platforms API
description: The built-in platforms, and platform plugins (opentide.plugins) that add a detection platform through the opentide.platforms entry point.
---

# Platforms API

The nine built-in platforms are the Rust core's connectors: the command line, the [Workspace](./workspace.md) and its [tenant operations](./workspace.md#tenant-operations) reach them, and `opentide.Connection.capabilities` says what each can do ([capability matrix](#capability-matrix)). Python adds a platform through a **plugin**.

The Python platform registry (`Opentide.Platforms`, `opentide.platforms`, the `declare()` entry points of the built-in platforms) is gone with the Python implementation ([#841](https://github.com/opentidehq/opentide/issues/841)).

## Platform plugins

A package can add a detection platform opentide does not ship: a **platform plugin**. It registers an `opentide.platforms` entry point named after the platform, pointing at an `opentide.plugins.PlatformPlugin`. The Rust core (the command line compiled into the package) discovers the entry points through the SDK layer and calls the plugin through PyO3, behind the same traits as the built-in platforms: `deploy` (`Deployer`), `validate_query` (`LiveValidator`), `run_query` (`QueryRunner`), and `check_configuration`, which `opentide validate` runs on each rule's block for the platform. The interpreter lock is held for the plugin call alone.

A runnable sample is in the repository: [`tests/fixtures/plugin_platform/`](https://github.com/opentidehq/opentide/tree/development/tests/fixtures/plugin_platform), the platform `acme`, which `tests/test_platforms/test_plugin_hook.py` deploys, validates and queries against a recorded stand-in tenant.

<Steps>

<Step>

### Implement the plugin

Subclass `PlatformPlugin` and override what the platform supports. A method you do not override is a capability the platform does not have: `opentide validate query --live` answers `supported: false` for a plugin without `validate_query`, as for the built-in platforms that cannot check a query. Never override one to fake success.

```python
from pydantic import BaseModel, ConfigDict, Field

from opentide.plugins import (
    DeployRequest,
    DeployResult,
    LiveCheck,
    PlatformPlugin,
    PlatformRefused,
    QueryRequest,
    QueryResult,
    Tenant,
)


class AcmeConfig(BaseModel):
    """A rule's configurations.acme block."""

    model_config = ConfigDict(extra="forbid")

    status: str | None = None
    query: str
    severity: int = Field(ge=1, le=5)


class AcmePlatform(PlatformPlugin):
    configuration_model = AcmeConfig

    def deploy(self, tenant: Tenant, request: DeployRequest) -> DeployResult:
        block = request.body["configuration"]
        if request.operation == "create":
            ...  # create the rule from block["query"]; the platform answers its id
            return DeployResult(remote_id="acme-rule-17")
        ...  # update, disable or delete the rule request.remote_id names
        return DeployResult(remote_id=request.remote_id)

    def validate_query(self, tenant: Tenant, request: QueryRequest) -> LiveCheck:
        ...  # ask the tenant whether request.text runs
        return LiveCheck()

    def run_query(self, tenant: Tenant, request: QueryRequest) -> QueryResult:
        ...  # search request.start to request.end, at most request.limit rows
        return QueryResult(rows=[{"host": "ws-1", "process": "cmd.exe"}])
```

</Step>

<Step>

### Register the entry point

```toml
[project.entry-points."opentide.platforms"]
acme = "acme_opentide:AcmePlatform"
```

The name is the platform's identifier: lower case letters, digits and `_`, starting with a letter. It is the key of the platform's block under a rule's `configurations` and the name of its configuration file. The entry point may name a `PlatformPlugin` subclass (built with no arguments), an instance, or a function that returns one. A plugin cannot take a built-in platform's name.

</Step>

<Step>

### Configure the workspace

Install the package into the environment opentide runs from, then enable the platform and its tenants in `.opentide/configurations/platforms/acme.toml`, as for a built-in platform:

```toml
[platform]
enabled = true
name = "Acme"

[[tenants]]
name = "lab"
[tenants.setup]
url = "$ACME_URL"
token = "$ACME_TOKEN"
```

Rules give the platform a block under `configurations.acme`. `opentide validate` checks it with `configuration_model` (or your own `check_configuration`), and reports each problem as a `schema_validation` finding at its line and column in the rule file, its message prefixed with the platform: `acme: Input should be a valid integer`.

</Step>

<Step>

### Run it

Plugin platforms run on the Rust core, with nothing to set: `validate` checks each rule's block for an enabled plugin's platform, and `query`, `validate query` and `deploy` take its name as `--platform`. `<plugin>` is the entry point's name (`acme` in the sample):

```bash
opentide validate
opentide deploy --platform <plugin> --strategy PREVIEW --all   # or --uuid, --file; --dry-run sends nothing
opentide validate query --live --platform <plugin>
opentide query --platform <plugin> --since 1h 'process | head'
```

`opentide validate` and the SDK's `opentide.Workspace.validate` check each plugin block with the plugin's model. `query --rule` and `--file` read a built-in platform's block: on a plugin's platform, give the query as `QUERY` or `--query-file` (`usage_invalid_value` otherwise).

</Step>

</Steps>

### What a plugin receives

| Type | Fields |
|------|--------|
| `Tenant` | `platform`, `name`, `setup` (its `[tenants.setup]` table, every `$NAME` resolved: never log a value), `lists` (its lists of strings), `verify_tls` (its `ssl`), `timeout` (seconds) |
| `DeployRequest` | `rule_id` (the rule's UUID), `operation` (`create`, `update`, `disable` or `delete`: see [Deployment](#deployment)), `remote_id` (the id an earlier `create` returned, for the other three), `body`: `{"rule": <the rule document>, "configuration": <its block for the platform>}`, the tenant's `[[modifiers]]` applied |
| `QueryRequest` | `text`, `language` (`--language`, or the block's `language` for a live check), `start` and `end` (UTC, `2026-11-01T00:00:00.000Z`), `limit`, `index`, `data_view`, `timeout` |

### What it returns

| Method | Returns | Fails with |
|--------|---------|------------|
| `deploy` | `DeployResult(remote_id, operation)`: a `create` returns the platform's id of the rule | `PlatformRefused(message, detail)`: the tenant refused the rule; `PlatformAuthenticationError`: it refused the credentials |
| `validate_query` | `LiveCheck(errors, warnings, result)`: `errors` fail the query although the tenant ran it | `PlatformRefused` for a query the tenant refuses |
| `run_query` | `QueryResult(rows, columns, truncated, partial, warnings, ...)`: at most `limit` rows, each a dict in column order | as `deploy` |
| `check_configuration` | a list of `ConfigurationFinding(path, message, warning)`, `path` inside the block | |

Any other exception fails the call with its type and message. In `query` and `validate query --live` it fails that tenant's run, and the other tenants still run; in `deploy` it stops the run, as a built-in platform's failure does.

`validate query --live` checks each rule's `configurations.<platform>.query`.

### Deployment

A plugin platform deploys as the built-in platforms that keep the vendor's id of a rule do (CrowdStrike, Defender for Endpoint, SentinelOne, Sysdig):

- `--strategy` is required, and the block's `status` decides whether a run sends the rule, as for every platform: `PREVIEW` and `RELEASE` runs, tenants' `strategies`, `--wide`, `--keep-deprecated`. `--dry-run` shows the plan and the block each tenant would receive, and sends nothing.
- Each rule is planned from its [deployment state](../usage/concepts/deployment-state.md) shard, `.opentide/states/deployment/<uuid>.json`, where the plugin's ids sit under `platforms.<plugin>.<tenant>`. Without an id there, the plugin receives `create`, and the `remote_id` it returns is recorded. With one, it receives `update`, `disable` (a status whose strategy is `DISABLEMENT`) or `delete` (`DELETION`), with that id as `remote_id`; after a `delete`, the id is forgotten. A `disable` or `delete` of a rule with no recorded id is skipped with `external_id_missing`, as for the built-in platforms.
- A `create` that returns no `remote_id` fails the rule: nothing could be recorded, and the next deploy would create the rule again. A platform that addresses rules by the rule's UUID returns `request.rule_id`. An `update` that returns another id than the recorded one replaces it.
- In CI, a `create` outside the production job is refused before the plugin is called (`deployment_state_unpersisted`), unless `--persist-state-externally` says the pipeline commits the shards itself.

### Where plugins are unavailable

Plugins load only when opentide runs from its Python package. The native binary (`opentide-cli`) and the npm package `@opentide/opentide` cannot import Python: there, `opentide validate` warns about each enabled platform that is not built in, with the way out, and `--platform` takes the built-in platforms only. The warning reads:

```text
acme is not a built-in platform: if it is a platform plugin (an opentide.platforms entry point), it loads only when opentide runs from its Python package (pip install opentide, then opentide ...); this command line cannot check its configuration or reach its tenants
```

Inside the package, `validate` warns instead about an enabled platform no installed plugin provides, and about a plugin that failed to load.

### Before 0.24: `declare()`

Earlier releases documented a plugin as a `declare()` function returning deployer and validator factories. The Python registry that listed them is gone: write a `PlatformPlugin`.

## Capability matrix

Human-readable table and the fields each block must contain: [Usage: Platforms](../usage/concepts/platforms.md). The normative field contracts are the [platform specs](/docs/specifications/specs/platforms/) (`platform::<identifier>::1.0`). Python models are listed on [Models](./models.md#platform-configuration-models).

## Source

`src/opentide/plugins.py` (the plugin API), `crates/opentide-connectors/src/plugin.rs` and `bindings/python/src/plugins.rs` (the hook), `crates/opentide-connectors/` (the built-in platforms)
