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
| `--file` | Validate one YAML file — repo-relative path, absolute path, or bare file name |
| `--uuid` | Validate specific UUIDs (repeatable) |
| `--type` | Filter by object type (repeatable) |
| `--strict` | Treat warnings as failures (exit `1`) |

`--strict` fails warning runs with exit `1`. Without it, warnings are reported in output and the process still exits `0`. Validation failures in `--json` mode include the complete report before the process exits.

Filename conventions and recommended metadata are **not** schema errors — use [`opentide lint`](./lint.md).

### Unparseable object files

An object file that is not valid YAML is reported as a `yaml_parse` issue against that path (exit `1`, and a complete report in `--json` mode) instead of raising a parser traceback. The file is not indexed, so no other check can see it — the issue is emitted regardless of `--check`.

### CVE check

`opentide validate --check cve` looks up each `threat.cve` identifier on [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) (`GET /api/vulnerability/{id}`). Unknown IDs (empty JSON body) fail the check. Links in generated docs use the same aggregator: `https://vulnerability.circl.lu/vuln/{id}`.

Accepted identifiers:

- CVE (`CVE-2024-3094`)
- GitHub Security Advisories (`GHSA-rxwq-x6h5-x525`)
- GCVE, including GNA 0 which maps to CVE (`GCVE-0-2024-3094` is stored as `CVE-2024-3094`)

The check no longer scrapes NVD through `mitrecve`. If Vulnerability-Lookup is unreachable, those identifiers are skipped (logged) rather than reported as invalid.

### Default checks

When no `--check` is specified, the pipeline runs:

- `id-uniqueness`
- `uuid-format`
- `schema` (includes vocabulary and cross-object references)

CVE lookup is **opt-in**: pass `--check cve`. It is not part of the default CLI pipeline so offline `opentide validate` stays deterministic.

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
