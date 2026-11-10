---
title: Models
description: The Tide models for rules, objectives, and threats — frozen Rust classes with the Pydantic methods, key fields, delegation helpers, results, and errors.
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

The YAML you author maps one-to-one onto these attributes. The [registry](./registry.md) still loads the CLI's Pydantic models, which have the same attributes; `opentide.models.delegation.from_yaml_dict(document)` reads a document into the Rust class its `metadata.schema` names:

```python
rule = Opentide.Rules["00000000-0000-4000-8003-000000000001"]
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
obj = Opentide.Objectives["00000000-0000-4000-8002-000000000001"]
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
threat = Opentide.Threats["00000000-0000-4000-8001-000000000001"]
threat.threat.mitre_attack      # ["T1059"]  (YAML `mitre_attack`)
threat.threat.terrain           # free-form prose
threat.threat.surface           # vocabulary list, e.g. ["OS::Windows::Desktop"]
threat.threat.impact            # vocabulary list, e.g. ["Data Breach", "Identity Theft"]
threat.threat.cve               # list[str] | None, e.g. ["CVE-2024-3094"] — CIRCL Vulnerability-Lookup (CVE, GHSA, GCVE)
threat.threat.actors            # list[ThreatActor] | None; name is scoped (att&ck::G0006)
```

## Delegation methods

Rules loaded through the [registry](./registry.md) are bound to it and expose operations directly. A Rust class cannot carry them (it is frozen and cannot be subclassed): for a rule from `opentide.models`, `opentide.models.delegation` has each one as a function, `validate(rule)`, `validate_query(rule, platform)`, `run_query(rule, platform, ...)`, `deploy(rule, platform, dry_run=False, *, strategies=None)`, `document(rule)` and `promote(rule, status)`, each taking an optional `registry=` (default `Opentide`). `Opentide.render_rule(rule)` and `Opentide.validate_rule(rule)` take either kind of rule.

```python
rule = Opentide.Rules[uuid]

rule.validate() -> ValidationResult                      # schema + cross-object checks
rule.validate_query(platform) -> ValidationResult        # query syntax (supported platforms)
rule.run_query(platform, *, tenants=(), since=None, limit=100) -> QueryRun  # rows from the tenants
rule.deploy(platform, dry_run=False, *, strategies=None) -> DeploymentResult
rule.document() -> str                                   # or Opentide.render_rule(rule)
```

`validate_query` runs the platform's query validator when one exists (Sentinel, Defender, Splunk, SentinelOne, Carbon Black); for CrowdStrike/HarfangLab it reports unsupported rather than faking a pass. See [Validation → query validation](./validation.md#query-validation).

`run_query` sends the query this rule deploys to *platform* to the tenants `tenants` names (`["all"]` for every one; none for the only one) over the last `since` (default `24h`), and returns an `opentide.query.QueryRun`: `outcomes` holds one `TenantOutcome` per tenant, with `result.columns` and `result.rows` or an `error`. A call that cannot run raises `opentide.query.QueryUsageError`. It is [`opentide query --rule`](../cli/query.md) in Python; `opentide.query.run_query(platform, query=...)` runs a query that is not a rule's.

<Callout type="warn">
`Opentide.promote_rule()` raises `NotImplementedError` — change rule `status` in YAML and use `opentide deploy` (promotion runs inside deploy when configured).
</Callout>

## Results

Delegation methods and helpers return small Pydantic result models (`opentide.models.results`):

```python
class ValidationResult(BaseModel):
    ok: bool
    errors: list[str] = []
    warnings: list[str] = []

class DeploymentResult(BaseModel):
    platform: str
    uuids: list[str]
    dry_run: bool = False
    message: str = ""
```

```python
result = rule.validate()
if not result.ok:
    for err in result.errors:
        print(err)
```

## Errors

Exceptions live under `opentide.core.errors.Errors`. Catch the specific type you expect:

| Exception | Raised when |
|-----------|-------------|
| `Errors.TideDataModelErrors` | Malformed Tide object (bad structure) |
| `Errors.TideRuleDataModelErrors` | Invalid detection rule data structure. `Errors.TideMDRDataModelErrors` is the former name, kept as an alias |
| `Errors.TideQueryValidationError` | A rule query fails validation |
| `Errors.TideDeploymentErrors` | Any failure during deployment |
| `Errors.TenantConnectionError` | Cannot connect to the target tenant. Live query validation raises the subclass `TenantUnreachableError` (`opentide.platforms.transport`), which names the `tenant` and `host`, and counts in `timeouts` the queries in a row that got no answer when that is why |
| `Errors.DetectionRuleCreationFailed` / `…UpdateFailed` / `…DeletionFailed` | Platform API operation failed |
| `Errors.TideConfigurationErrors` | Invalid opentide configuration files |
| `Errors.TenantNonExistingDeploymentPlan` | A tenant references a missing deployment plan |

```python
from opentide.core.errors import Errors

try:
    rule.deploy("sentinel")
except Errors.TenantConnectionError:
    ...  # credentials / connectivity
except Errors.TideDeploymentErrors:
    ...  # deployment failure
```

Note the difference between **results** (returned for expected pass/fail outcomes like validation) and **errors** (raised for exceptional failures like a broken connection).

## Loading without the registry

```python
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.loading.object_loader import load_object_for_validation
```

Prefer registry access for interactive work; these loaders are used internally by validation and indexing.

Both pick the model from `metadata.schema`. A missing identifier raises `SchemaMissingError` (a `ValueError` from `opentide.loading.object_loader`). An unknown identifier, or one of another object type, raises `SchemaIdentifierError` (a `LookupError` from the same module). Neither falls back to the newest revision.

## Source

`src/opentide/models/` (the public package), `crates/opentide-schema/src/python.rs` (the classes), `src/opentide/_models/` (the CLI's Pydantic models, `results.py`), `src/opentide/core/errors.py`
