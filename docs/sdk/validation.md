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

Default pipeline checks: id uniqueness, UUID format, schema.

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

Query validators live under platform plugins — use CLI `opentide validate query` or MCP `validate_query` (stub until live integration ships).

## Source

`src/opentide/validation/session.py`, `src/opentide/validation/scope.py`, `src/opentide/validation/issues.py`
