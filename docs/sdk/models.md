---
title: Models
description: Pydantic models for rules, objectives, and threats — key fields, delegation methods, results, and errors.
---

# Models

Core objects are Pydantic v2 models with explicit schema identifiers. This page is the Python-side field reference; the full normative field contract lives in the [specifications](/docs/specifications/).

## Core objects

| Model | Schema ID | Module | Spec |
|-------|-----------|--------|------|
| `DetectionRule` | `rule::1.0` | `opentide.models.rule` | [rule-1.0](/docs/specifications/specs/objects/rule-1.0/) |
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
| `metadata` | `ObjectMetadata` | Identity, schema, version, tlp |
| `description` | `str` | Rule narrative |
| `status` | `str` | Deployment status (default `STAGING`) |
| `severity` | `str` | Severity vocabulary (default `Informational`) |
| `techniques` | `list[str]` | ATT&CK technique IDs |
| `configurations` | `RuleConfigurations` | Typed per-platform blocks (preferred) |
| `platforms` | `dict` | Legacy flat platform dict |
| `detection_model` | `str \| None` | Objective UUID this rule implements |
| `response` | `RuleResponse \| None` | Alert + response playbook |

The YAML you author maps one-to-one onto these attributes:

```python
rule = OpenTide.Rules["00000000-0000-4000-8003-000000000001"]
rule.name                       # "Sentinel KQL Rule"
rule.metadata.schema            # "rule::1.0"
rule.detection_model            # objective UUID
rule.configurations.sentinel.query
```

## DetectionObjective — key fields

| Attribute | Type | Notes |
|-----------|------|-------|
| `name` | `str` | Display name |
| `metadata` | `ObjectMetadata` | Shared metadata |
| `composition` | `ObjectiveComposition` | Top-level strategy (mirrors `objective.composition`) |
| `objective` | `ObjectiveBody` | Body: `priority`, `type`, `signals`, `threats`, … |

```python
obj = OpenTide.Objectives["00000000-0000-4000-8002-000000000001"]
obj.objective.threats           # ["…8001…"]  (threat UUIDs)
[s.name for s in obj.objective.signals]
```

## ThreatVector — key fields

| Attribute | Type | Notes |
|-----------|------|-------|
| `name` | `str` | Display name |
| `criticality` | `str` | Criticality vocabulary |
| `metadata` | `ObjectMetadata` | Shared metadata |
| `threat` | `ThreatBody` | Body: `severity`, `impact`, `terrain`, `surface`, `att&ck`, … |

```python
threat = OpenTide.Threats["00000000-0000-4000-8001-000000000001"]
threat.threat.att_ck            # ["T1059"]  (YAML `att&ck`, aliased att_ck)
threat.threat.terrain           # free-form prose
threat.threat.surface           # vocabulary list, e.g. ["Windows::Desktop"]
```

## Delegation methods

Rules loaded through the [registry](./registry.md) are bound to it and expose operations directly:

```python
rule = OpenTide.Rules[uuid]

rule.validate() -> ValidationResult                      # schema + cross-object checks
rule.validate_query(platform) -> ValidationResult        # query syntax (supported platforms)
rule.deploy(platform, dry_run=False) -> DeploymentResult
rule.document() -> str                                   # or OpenTide.render_rule(rule)
```

`validate_query` runs the platform's query validator when one exists (Sentinel, Defender, Splunk, SentinelOne, Carbon Black); for CrowdStrike/HarfangLab it reports unsupported rather than faking a pass. See [Validation → query validation](./validation.md#query-validation).

<Callout type="warn">
`OpenTide.promote_rule()` raises `NotImplementedError` — change rule `status` in YAML and use `opentide deploy` (promotion runs inside deploy when configured).
</Callout>

## Results

Delegation methods return small Pydantic result models (`opentide.models.results`):

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

Exceptions live under `opentide.core.errors.Errors` (aliased `TideErrors`). Catch the specific type you expect:

| Exception | Raised when |
|-----------|-------------|
| `Errors.TideDataModelErrors` | Malformed Tide object (bad structure) |
| `Errors.TideMDRDataModelErrors` | Invalid MDR (rule) data structure |
| `Errors.TideQueryValidationError` | A rule query fails validation |
| `Errors.TideDeploymentErrors` | Any failure during deployment |
| `Errors.TenantConnectionError` | Cannot connect to the target tenant |
| `Errors.DetectionRuleCreationFailed` / `…UpdateFailed` / `…DeletionFailed` | Platform API operation failed |
| `Errors.TideConfigurationErrors` | Invalid OpenTide configuration files |
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

## Source

`src/opentide/models/`, `src/opentide/models/results.py`, `src/opentide/core/errors.py`
