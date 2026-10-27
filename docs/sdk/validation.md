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

`files` follows the [`validate --file`](../cli/validate.md#selecting-a-file) rules: a path matches only the file it names, a bare file name matches that name in every object folder. Files in subfolders are not objects and match nothing; the report carries a `nested_object_file` warning for each one in scope. Relative paths resolve against the working directory and the workspace root; `roots=` replaces the workspace root with the directories you pass.

## Check selection

```python
from opentide.validation.checks.kinds import ValidateCheck

report = run_validation(
    scope=ValidationScope.full(),
    checks=frozenset({ValidateCheck.schema, ValidateCheck.cve}),
)
```

Available checks: `id-uniqueness`, `uuid-format`, `schema`, `configuration`, `cve`, `sharing-config`.

The `cve` check looks up `threat.cve` identifiers on [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) (`GET /api/vulnerability/{id}`). An empty JSON object means the identifier is unknown. The check does not scrape NVD through `mitrecve`. CVE, GHSA, and GCVE identifiers are accepted; GNA 0 GCVE ids (`GCVE-0-YEAR-N`) are stored under the corresponding `CVE-YEAR-N` key.

Default pipeline checks: id uniqueness, UUID format, schema, configuration. CVE lookup is opt-in via `ValidateCheck.cve`, and the `sharing.toml` check via `ValidateCheck.sharing_config`. The configuration check is workspace-wide, so a narrowed scope skips it unless it is the only check requested; see [Configuration models](./configuration.md).

## ValidationReport

Structured report with:

- `ok` — overall pass/fail
- `errors`, `warnings` — `ValidationIssue` lists
- `model_dump_json_ready()` — JSON-safe dict for APIs

MCP `validation_report` tool returns this shape, with the [diagnostic fields](../mcp/tools.md#diagnostic-fields) added to each issue and a `next_actions` list.

## Single rule via registry

```python
from opentide import Opentide

Opentide.initialise()
rule = Opentide.Rules[uuid]
result = Opentide.validate_rule(rule)
```

`validate_rule` checks the rule against the revision its `metadata.schema` names, so a `rule::1.1` rule may carry `metadata.reviewed` and a `rule::1.0` rule may not. Through 0.15.0 `validate_rule` checked every rule against `rule::1.0`, so a valid `rule::1.1` rule that carried `metadata.reviewed` failed.

A loaded rule always declares a registered identifier: `Opentide.Rules` and `load_rule_from_dict` raise `SchemaMissingError` or `SchemaIdentifierError` instead (see [Loading without the registry](./models.md#loading-without-the-registry)). To check a raw YAML body, use `validate_raw_payload`:

```python
from opentide.validation import validate_raw_payload

result = validate_raw_payload(body, "rule")
```

It checks the body against the revision its `metadata.schema` names. A body without `metadata.schema` fails with `schema_missing: missing metadata.schema on object`. An unknown identifier, or one of another object type, fails on `('metadata', 'schema')`. Neither is checked against the newest revision. [`opentide validate`](../cli/validate.md#schema-identifier) reports the same cases as issues.

## Query validation

Query validation is a **platform plugin** concern, separate from object validation above. Two Python paths exist:

```python
from opentide import Opentide
Opentide.initialise()

rule = Opentide.Rules[uuid]
result = rule.validate_query("sentinel")   # ValidationResult
print(result.ok, result.errors)
```

`rule.validate_query(platform)` delegates to the platform's registered **live** validator, which needs the vendor SDK and tenant credentials. It works for the six platforms that ship validators — `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`, `elastic` — and reports **unsupported** (not a fake pass) for `crowdstrike` and `harfanglab`. Check capability first:

```python
if Opentide.Platforms["sentinel"].can_validate:
    result = rule.validate_query("sentinel")
```

### The tenant check

There is no in-process query scanner. A bare `opentide validate query` refuses and names `--live`. `--live` and `rule.validate_query(platform)` both call the tenant. A missing SDK or a missing plan fails that check.

<Callout type="info">
Three entry points, three behaviours — pick deliberately:

| Entry point | Behaviour |
|---|---|
| `rule.validate_query(platform)` | Live vendor call. Needs a configured tenant. |
| `opentide validate query` | Refuses until you pass `--live`. |
| MCP `validate_query` | Refuses until you pass `live: true`, which calls the tenant. |

See [MCP tools](../mcp/tools.md).
</Callout>

A failed query validation may raise `Errors.TideQueryValidationError` for exceptional cases; expected pass/fail is returned in the `ValidationResult`. See [Models → errors](./models.md#errors).

## Source

`src/opentide/validation/session.py`, `src/opentide/validation/scope.py`, `src/opentide/validation/issues.py`
