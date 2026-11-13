---
title: Models
description: The Tide models for rules, objectives, and threats — frozen Rust classes with the Pydantic methods, their key fields, and where the operations the registry bound to them went.
---

# Models

The classes in `opentide.models` are the Tide models compiled into opentide: frozen Rust classes under the names the Pydantic models had, with explicit schema identifiers. This page is the Python-side field reference; the full normative field contract lives in the [specifications](/docs/specifications/).

They keep the Pydantic methods SDK code calls: `model_validate`, `model_validate_json`, `model_dump`, `model_dump_json`, `model_copy` and `model_json_schema`, field access, `==`, `hash`, `repr` and pickling. They are frozen: setting an attribute raises, and `model_copy(update=...)` gives a validated copy. `model_validate` raises `opentide.models.ValidationError`, a `ValueError` whose `errors()` lists every error with Pydantic's `type`, `loc` and `msg`. `model_fields`, `model_construct`, `model_rebuild` and `model_post_init` still work, with a `DeprecationWarning`, for one minor release. Importing `opentide.models` loads no Pydantic.

```python
from opentide.models import DetectionRule, DetectionRule_v1_1, ValidationError
DetectionRule_v1_1.__schema_identifier__  # "rule::1.1"
DetectionRule.__module__                   # "opentide._native.models"
issubclass(ValidationError, ValueError)    # True
```

## Core objects

| Model | Schema ID | Module | Spec |
|-------|-----------|--------|------|
| `DetectionRule` | `rule::1.0` | `opentide.models.rule` | [rule-1.0](/docs/specifications/specs/objects/rule-1.0/) |
| `DetectionRule_v1_1` | `rule::1.1` | `opentide.models.rule` | [rule-1.1](/docs/specifications/specs/objects/rule-1.1/) |
| `DetectionObjective` | `objective::1.0` | `opentide.models.objective` | [objective-1.0](/docs/specifications/specs/objects/objective-1.0/) |
| `ThreatVector` | `threat::1.0` | `opentide.models.threat` | [threat-1.0](/docs/specifications/specs/objects/threat-1.0/) |

```python
from opentide.models.rule import DetectionRule
DetectionRule.__schema_identifier__  # "rule::1.0"
```

## DetectionRule — key fields

| Attribute | Type | Notes |
|-----------|------|-------|
| `name` | `str` | Display name |
| `metadata` | `ObjectMetadata` | Identity (`uuid`), `schema_id`, `version`, `tlp` |
| `description` | `str` | Rule narrative |
| `status` | `str \| None` | Read by no command; `None` when left out. A rule deploys, and promotion moves it, by each platform block's `status` (`platform_statuses`) |
| `severity` | `str \| None` | Severity vocabulary, `None` when left out. Deploy sends `response.alert_severity`; `displayed_severity` is that, else this |
| `techniques` | `list[str]` | ATT&CK technique IDs |
| `configurations` | `RuleConfigurations` | Typed per-platform blocks (preferred) |
| `platforms` | `dict` | Legacy flat platform dict |
| `detection_model` | `str \| None` | UUID of the objective, or of a signal under it, that this rule implements |
| `response` | `RuleResponse \| None` | Alert + response playbook |

The YAML you author maps one-to-one onto these attributes. Read an object file into the class its `metadata.schema` names (the package reads no YAML itself: `pip install pyyaml`, or any YAML 1.2 reader), or let [`Workspace`](./workspace.md) read the whole workspace:

```python
import yaml
from opentide.models import DetectionRule, DetectionRule_v1_1

REVISIONS = {"rule::1.0": DetectionRule, "rule::1.1": DetectionRule_v1_1}
with open("objects/rules/rule-0001-sentinel-kql.yaml", encoding="utf-8") as file:
    document = yaml.safe_load(file)
rule = REVISIONS[document["metadata"]["schema"]].model_validate(document)
```

```python
rule.name                       # "Sentinel KQL Rule"
rule.metadata.schema_id         # "rule::1.0"  (YAML `metadata.schema`)
rule.metadata.schema            # "rule::1.0"  (read-only alias of schema_id)
rule.detection_model            # objective UUID (or a signal UUID under one)
rule.configurations.sentinel.query
```

`ObjectMetadata.schema_id` is the field. Validation accepts it under the YAML key `schema` or as `schema_id`, and `model_dump(by_alias=True)["schema"]` writes it back under `schema`. Platform blocks follow the same pattern: `platform_schema` is the field, and `rule.configurations.sentinel.schema` reads it (`None` when the block declares no `schema`). In 0.5.0 and earlier, `.schema` on either model returned Pydantic's deprecated `BaseModel.schema` method, not the identifier; read `schema_id` if your code must support those releases.

## Platform configuration models

`rule.configurations` is a `RuleConfigurations` (`opentide.models.platform`). Each block subclasses `PlatformConfigBase` (`enabled`, `name`, `platform_schema`, `status`, `flags`, `tenants`, `contributors`). Nested objects live in `opentide.models.platform_configs`. The normative field contract is the platform spec, not this table.

| Model | YAML key | Schema ID | Spec |
|-------|----------|-----------|------|
| `SentinelConfig` | `sentinel` | `platform::sentinel::1.0` | [sentinel-1.0](/docs/specifications/specs/platforms/sentinel-1.0/) |
| `DefenderConfig` | `defender_for_endpoint` | `platform::defender_for_endpoint::1.0` | [defender-for-endpoint-1.0](/docs/specifications/specs/platforms/defender-for-endpoint-1.0/) |
| `SplunkConfig` | `splunk` | `platform::splunk::1.0` | [splunk-1.0](/docs/specifications/specs/platforms/splunk-1.0/) |
| `SentinelOneConfig` | `sentinel_one` | `platform::sentinel_one::1.0` | [sentinel-one-1.0](/docs/specifications/specs/platforms/sentinel-one-1.0/) |
| `CrowdstrikeConfig` | `crowdstrike` | `platform::crowdstrike::1.0` | [crowdstrike-1.0](/docs/specifications/specs/platforms/crowdstrike-1.0/) |
| `HarfangLabConfig` | `harfanglab` | `platform::harfanglab::1.0` | [harfanglab-1.0](/docs/specifications/specs/platforms/harfanglab-1.0/) |
| `CarbonBlackConfig` | `carbon_black_cloud` | `platform::carbon_black_cloud::1.0` | [carbon-black-cloud-1.0](/docs/specifications/specs/platforms/carbon-black-cloud-1.0/) |
| `SysdigConfig` | `sysdig` | `platform::sysdig::1.0` | [sysdig-1.0](/docs/specifications/specs/platforms/sysdig-1.0/) |

```python
rule.configurations.sentinel.query
rule.configurations.sentinel.schema          # YAML `schema`, or None
rule.configurations.sentinel.scheduling.frequency  # "PT1H"
```

These classes implement the [platform specs](/docs/specifications/specs/platforms/). The specs list every key. This page only names the class that holds each block.

## DetectionObjective — key fields

| Attribute | Type | Notes |
|-----------|------|-------|
| `name` | `str` | Display name |
| `metadata` | `ObjectMetadata` | Shared metadata |
| `composition` | `ObjectiveComposition` | Top-level strategy (mirrors `objective.composition`) |
| `objective` | `ObjectiveBody` | Body: `priority`, `type`, `signals`, `threats`, … |

```python
obj                             # a DetectionObjective, read as the rule above
obj.objective.threats           # ["…8001…"]  (threat UUIDs)
[s.name for s in obj.objective.signals]
```

## ThreatVector — key fields

| Attribute | Type | Notes |
|-----------|------|-------|
| `name` | `str` | Display name |
| `criticality` | `str` | Criticality vocabulary |
| `metadata` | `ObjectMetadata` | Shared metadata |
| `threat` | `ThreatBody` | Body: `severity`, `impact` and `leverage` (non-empty `list[str]` of vocabulary names), `terrain`, `surface`, `att&ck`, `actors` (`list[ThreatActor]`), optional `cve` (`list[str]`, Vulnerability-Lookup IDs), … |

```python
threat                          # a ThreatVector, read as the rule above
threat.threat.mitre_attack      # ["T1059"]  (YAML `mitre_attack`)
threat.threat.terrain           # free-form prose
threat.threat.surface           # vocabulary list, e.g. ["OS::Windows::Desktop"]
threat.threat.impact            # vocabulary list, e.g. ["Data Breach", "Identity Theft"]
threat.threat.cve               # list[str] | None, e.g. ["CVE-2024-3094"] — CIRCL Vulnerability-Lookup (CVE, GHSA, GCVE)
threat.threat.actors            # list[ThreatActor] | None; name is scoped (att&ck::G0006)
```

## Operations on a model

The models are data: frozen, with nothing bound to a workspace. What the registry's rules had as methods (`rule.validate()`, `rule.deploy(...)`, `rule.document()`, and `opentide.models.delegation` for the Rust classes) is the workspace's and the tenant's, since the Python implementation was removed:

| Was | Now |
|-----|-----|
| `rule.validate()` | `Workspace.open(".").validate(uuids=[uuid])` ([Workspace](./workspace.md#validate)) |
| `rule.validate_query(platform)` | `await Connection.open(tenant).validate_query(...)` ([tenant operations](./workspace.md#tenant-operations)), or `opentide.analysis.check_query` offline ([Query checks](./validation.md)) |
| `rule.run_query(platform, ...)` | `await Connection.open(tenant).query(...)` |
| `rule.deploy(platform, dry_run=True)` | `ws.deploy_plan(uuids=[uuid])`; a real deploy, `ws.run_json(["deploy", "--uuid", uuid, ...])` or `await Connection.open(tenant).deploy(...)` |
| `rule.document()` | `ws.run_json(["generate", "docs", "rules"])` |

A call that cannot run raises `opentide.OpentideError`, whose `code` is stable ([errors](./workspace.md#errors)); `opentide.models.ValidationError` is what `model_validate` raises.
