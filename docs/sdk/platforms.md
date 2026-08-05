---
title: Platforms API
description: Platform registry, entry-point plugins, deployers, and query validators.
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
from opentide import OpenTide

OpenTide.initialise()
for name, platform in OpenTide.Platforms.items():
    print(name, platform.enabled, platform.can_deploy, platform.can_validate)
```

## Platform dataclass

| Field | Description |
|-------|-------------|
| `name` | Registry key (e.g. `defender_for_endpoint`) |
| `enabled` | Whether platform is active in client config |
| `config` | Loaded platform configuration |
| `deployer` | Rule deployer instance or None |
| `validator` | Query validator instance or None |
| `can_deploy` | Property — deployer present |
| `can_validate` | Property — validator present |

## Query validators

Five platforms register validators (see `QUERY_VALIDATION_PLATFORMS` in `opentide.cli.enums`):

- `sentinel` → KQL
- `defender_for_endpoint` → KQL
- `splunk` → SPL
- `sentinel_one` → S1QL
- `carbon_black_cloud` → Lucene

CrowdStrike and HarfangLab have deployers only.

## Rule deployment

```python
rule = OpenTide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
print(result.dry_run, result.message)
```

## Plugin declaration

Each platform module exposes `declare()` returning deployer/validator factories. Client enablement is read from `.opentide/configurations/platforms/`.

## Authoring a custom platform plugin

You can add support for a platform OpenTide does not ship by publishing a small package that registers an `opentide.platforms` entry point. At a high level:

<Steps>

<Step>

### Implement a `declare()`

Expose a `declare()` callable in your module that returns the platform's deployer and (optionally) query validator factories. Return only a deployer if the platform cannot validate queries — never return a validator that fakes success.

```python
# my_opentide_acme/__init__.py
def declare():
    from .deployer import AcmeDeployer
    return {
        "identifier": "acme",
        "name": "Acme SIEM",
        "deployer": AcmeDeployer,     # required for deploy support
        "validator": None,            # None → can_validate is False
    }
```

</Step>

<Step>

### Register the entry point

In your package's `pyproject.toml`:

```toml
[project.entry-points."opentide.platforms"]
acme = "my_opentide_acme:declare"
```

Install the package into the same environment as `opentide`; the registry discovers it at `OpenTide.initialise()`.

</Step>

<Step>

### Provide a rule configuration model

Define the typed block that appears under `configurations.acme` in rule YAML, following the shared platform-block fields from [rule-1.0](/docs/specifications/specs/objects/rule-1.0/) plus your platform's query fields. Declare its schema id as `platform::acme::1.0`.

</Step>

<Step>

### Verify

```python
OpenTide.initialise()
plat = OpenTide.Platforms["acme"]
assert plat.can_deploy and not plat.can_validate
```

</Step>

</Steps>

<Callout type="warn">
Honesty is a hard requirement: a platform with no real query validator MUST report `can_validate=False` (return `validator=None`). Do not return a validator that always passes — the CLI and MCP rely on this flag to avoid claiming false coverage.
</Callout>

## Capability matrix

Human-readable table: [Usage: Platforms](../usage/concepts/platforms.md).

## Source

`src/opentide/platforms/registry.py`, `src/opentide/platforms/plugins.py`
