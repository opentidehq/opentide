---
title: Platforms API
description: Platform registry, deployers and query validators, and platform plugins (opentide.plugins) that add a detection platform through the opentide.platforms entry point.
---

# Platforms API

Platforms register through setuptools entry points in `pyproject.toml`:

```toml
[project.entry-points."opentide.platforms"]
sentinel = "opentide.platforms.sentinel:declare"
splunk = "opentide.platforms.splunk:declare"
# …
```

## PlatformsRegistry

```python
from opentide import Opentide

Opentide.initialise()
for name, platform in Opentide.Platforms.items():
    print(name, platform.enabled, platform.can_deploy, platform.can_validate)
```

## Platform

`config`, `deployer` and `validator` are built the first time they are read. Listing platforms (`opentide info`, the MCP platforms resource) therefore never builds a client or reads the tenant configuration of a platform you do not use.

| Field | Description |
|-------|-------------|
| `name` | Registry key (e.g. `defender_for_endpoint`) |
| `enabled` | Whether platform is active in client config |
| `config` | Loaded platform configuration, built on first access |
| `deployer` | Rule deployer instance or None, built on first access |
| `validator` | Query validator instance or None, built on first access |
| `can_deploy` | Property — the platform declares a deployer (does not build it) |
| `can_validate` | Property — the platform declares a validator (does not build it) |

## Query validators

Six platforms register validators (see `QUERY_VALIDATION_PLATFORMS` in `opentide.cli.enums`):

- `sentinel` → KQL
- `defender_for_endpoint` → KQL
- `splunk` → SPL
- `sentinel_one` → S1QL
- `carbon_black_cloud` → Lucene
- `elastic` → Kuery, Lucene, EQL, ES|QL (live tenant check only)

CrowdStrike, HarfangLab and Sysdig have deployers only.

## Rule deployment

```python
rule = Opentide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
print(result.dry_run, result.message)
```

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
        ...  # send block["query"] to tenant.setup["url"] with tenant.setup["token"]
        return DeployResult(remote_id="acme-rule-17")

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

Plugin platforms run on the Rust core: set `OPENTIDE_ENGINE=rust` (the Python CLI's `--platform` takes the built-in platforms only), or call `python -m opentide.cli.rust`. `<plugin>` is the entry point's name (`acme` in the sample):

```bash
export OPENTIDE_ENGINE=rust
opentide validate
opentide deploy --platform <plugin> --all          # or --uuid, --file; --dry-run sends nothing
opentide validate query --live --platform <plugin>
opentide query --platform <plugin> --since 1h 'process | head'
```

`OPENTIDE_ENGINE=compare` refuses a plugin run, since both runs would reach the tenant.

</Step>

</Steps>

### What a plugin receives

| Type | Fields |
|------|--------|
| `Tenant` | `platform`, `name`, `setup` (its `[tenants.setup]` table, every `$NAME` resolved: never log a value), `lists` (its lists of strings), `verify_tls` (its `ssl`), `timeout` (seconds) |
| `DeployRequest` | `rule_id` (the rule's UUID), `operation` (`create`: deploy creates or replaces), `body`: `{"rule": <the rule document>, "configuration": <its block for the platform>}` |
| `QueryRequest` | `text`, `language` (`--language`, or the block's `language` for a live check), `start` and `end` (UTC, `2026-11-01T00:00:00.000Z`), `limit`, `index`, `data_view`, `timeout` |

### What it returns

| Method | Returns | Fails with |
|--------|---------|------------|
| `deploy` | `DeployResult(remote_id, operation)` | `PlatformRefused(message, detail)`: the tenant refused the rule; `PlatformAuthenticationError`: it refused the credentials |
| `validate_query` | `LiveCheck(errors, warnings, result)`: `errors` fail the query although the tenant ran it | `PlatformRefused` for a query the tenant refuses |
| `run_query` | `QueryResult(rows, columns, truncated, partial, warnings, ...)`: at most `limit` rows, each a dict in column order | as `deploy` |
| `check_configuration` | a list of `ConfigurationFinding(path, message, warning)`, `path` inside the block | |

Any other exception fails that tenant's run with its type and message; the other tenants still run.

`validate query --live` checks each rule's `configurations.<platform>.query`. A deploy on a plugin platform does not record deployment state yet, and `--strategy` does not apply to it: every selected rule with the platform's block is sent to every tenant.

### Where plugins are unavailable

Plugins load only when opentide runs from its Python package. The native binary (`opentide-cli`) and the npm package `@opentide/opentide` cannot import Python: there, `opentide validate` warns about each enabled platform that is not built in, with the way out, and `--platform` takes the built-in platforms only. The warning reads:

```text
acme is not a built-in platform: if it is a platform plugin (an opentide.platforms entry point), it loads only when opentide runs from its Python package (pip install opentide, then OPENTIDE_ENGINE=rust opentide ...); this command line cannot check its configuration or reach its tenants
```

Inside the package, `validate` warns instead about an enabled platform no installed plugin provides, and about a plugin that failed to load.

### Before 0.24: `declare()`

Earlier releases documented a plugin as a `declare()` function returning deployer and validator factories. The Python registry still lists such entry points (`Opentide.Platforms`), but nothing deploys through them: write a `PlatformPlugin`.

## Capability matrix

Human-readable table and the fields each block must contain: [Usage: Platforms](../usage/concepts/platforms.md). The normative field contracts are the [platform specs](/docs/specifications/specs/platforms/) (`platform::<identifier>::1.0`). Python models are listed on [Models](./models.md#platform-configuration-models).

## Source

`src/opentide/plugins.py` (the plugin API), `crates/opentide-connectors/src/plugin.rs` and `bindings/python/src/plugins.rs` (the hook), `src/opentide/platforms/registry.py`, `src/opentide/platforms/plugins.py`
