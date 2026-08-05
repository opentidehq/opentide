---
title: opentide validate
description: Object validation (schema, UUID, uniqueness) and platform query syntax validation.
---

# opentide validate

Validates detection objects and platform query syntax.

## Object validation (default)

```bash
opentide validate
opentide validate --strict
opentide validate --file objects/rules/example.yaml
opentide validate --uuid <uuid> --uuid <uuid2>
opentide validate --type rule
opentide validate --check schema
```

### Options

| Flag | Purpose |
|------|---------|
| `--check` | Run a single check: `id-uniqueness`, `uuid-format`, `schema`, `cve` |
| `--file` | Validate one YAML file |
| `--uuid` | Validate specific UUIDs (repeatable) |
| `--type` | Filter by object type (repeatable) |
| `--strict` | Accepted for compatibility; does **not** change exit handling today (warnings still only soft-fail as `19` on GitLab) |

### Default checks

When no `--check` is specified, the pipeline runs:

- `id-uniqueness`
- `uuid-format`
- `schema`

Additional checks (cross-object references, vocabulary, CVE) run in the full validation session.

## Query validation

```bash
opentide validate query --platform sentinel
opentide validate query --platform splunk --plan STAGING --wide
```

| Flag | Purpose |
|------|---------|
| `--platform` | **Required.** Platform enum value |
| `--plan` | Deployment plan (`DEPLOYMENT_PLAN` env) |
| `--wide` | Wide output format |

### Supported platforms

Query validation works on **five platforms** only:

- `sentinel` (KQL)
- `defender_for_endpoint` (KQL)
- `splunk` (SPL)
- `sentinel_one` (S1QL)
- `carbon_black_cloud` (Lucene)

CrowdStrike and HarfangLab return unsupported — never fake validation.

## SDK equivalent

```python
from opentide.validation.session import run_validation
from opentide.validation.scope import ValidationScope

report = run_validation(scope=ValidationScope.full())
print(report.ok, len(report.errors))
```

See [SDK validation](../sdk/validation.md).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/validation.py`
