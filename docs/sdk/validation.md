---
title: Validation API
description: Programmatic validation with ValidationScope, ValidateCheck, and ValidationReport.
---

# Validation API

Headless validation for scripts, services, and MCP tools.

## Full registry validation

```python
from opentide.validation.session import run_validation
from opentide.validation.scope import ValidationScope

report = run_validation(scope=ValidationScope.full())
print(report.ok)
for issue in report.errors:
    print(issue.to_legacy_string())
```

## Narrow scope

```python
scope = ValidationScope.narrow(
    files=frozenset({"objects/rules/example.yaml"}),
    uuids=frozenset({"<uuid>"}),
    types=frozenset({"rule"}),
)
report = run_validation(scope=scope)
```

## Check selection

```python
from opentide.validation.checks.kinds import ValidateCheck

report = run_validation(
    scope=ValidationScope.full(),
    checks=frozenset({ValidateCheck.schema, ValidateCheck.cve}),
)
```

Available checks: `id-uniqueness`, `uuid-format`, `schema`, `cve`.

The `cve` check looks up `threat.cve` identifiers on [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) (`GET /api/vulnerability/{id}`). An empty JSON object means the identifier is unknown. The check does not scrape NVD through `mitrecve`. CVE, GHSA, and GCVE identifiers are accepted; GNA 0 GCVE ids (`GCVE-0-YEAR-N`) are stored under the corresponding `CVE-YEAR-N` key.

Default pipeline checks: id uniqueness, UUID format, schema. CVE lookup is opt-in via `ValidateCheck.cve`.

## ValidationReport

Structured report with:

- `ok` — overall pass/fail
- `errors`, `warnings` — `ValidationIssue` lists
- `model_dump_json_ready()` — JSON-safe dict for APIs

MCP `validation_report` tool returns this shape.

## Single rule via registry

```python
from opentide import OpenTide

OpenTide.initialise()
rule = OpenTide.Rules[uuid]
result = OpenTide.validate_rule(rule)
```

## Query validation

Query validation is a **platform plugin** concern, separate from object validation above. Two Python paths exist:

```python
from opentide import OpenTide
OpenTide.initialise()

rule = OpenTide.Rules[uuid]
result = rule.validate_query("sentinel")   # ValidationResult
print(result.ok, result.errors)
```

`rule.validate_query(platform)` delegates to the platform's registered validator. It works for the five platforms that ship validators — `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud` — and reports **unsupported** (not a fake pass) for `crowdstrike` and `harfanglab`. Check capability first:

```python
if OpenTide.Platforms["sentinel"].can_validate:
    result = rule.validate_query("sentinel")
```

<Callout type="info">
The **CLI** `opentide validate query` uses this same path and is the recommended entry point for CI. The **MCP** `validate_query` tool is a stub and does not parse queries — do not rely on it (see [MCP tools](../mcp/tools.md)). The SDK/CLI path is the real one.
</Callout>

A failed query validation may raise `Errors.TideQueryValidationError` for exceptional cases; expected pass/fail is returned in the `ValidationResult`. See [Models → errors](./models.md#errors).

## Source

`src/opentide/validation/session.py`, `src/opentide/validation/scope.py`, `src/opentide/validation/issues.py`
