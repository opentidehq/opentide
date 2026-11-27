---
title: Query checks
description: Check one query offline with opentide.analysis.check_query, or on a tenant with Connection.validate_query; validate a whole workspace with Workspace.validate.
---

# Query checks

A workspace's checks, its queries' included, are [`Workspace.validate`](./workspace.md#validate) and [`Workspace.lint`](./workspace.md#lint): the command line's `validate` and `lint`, with their codes and documents. Two calls check one query on its own.

## Offline, with the analysis engine

`opentide.analysis.check_query` checks a query in-process, with the engine `pip install opentide` installs (no tenant, no vendor SDK). It covers Sentinel and Defender KQL, Splunk SPL, Elastic (ES|QL, EQL, Kibana KQL, Lucene), Carbon Black and Graylog Lucene, CrowdStrike CQL, Sysdig's Falco conditions, HarfangLab's and Bitdefender's YARA (`yara`), the Exabeam Query Language (`exabeam`) and Google SecOps' YARA-L 2.0 (`yaral`):

```python
from opentide.analysis import check_query

findings = check_query("SecurityEvent | wher EventID == 4688", language="kql", platform="sentinel")
for finding in findings:
    print(finding.code, finding.severity, finding.line, finding.column, finding.message)
```

`position="rule"` checks the query as the platform's rule block checks its own, so a CrowdStrike query is a Next-Gen SIEM correlation rule and an Exabeam query a sequence filter, where a search (`position="search"`, the default) is not; `rule` needs a `platform` and raises `ValueError` without one:

```python
check_query(query, language="cql", platform="crowdstrike", position="rule")
```

Rust's `opentide::analysis::analyze_query` takes the same through `QueryRequest::new(language, text).with_platform(Some(...)).with_position(QueryPosition::Rule)`. A rule without a platform is not checked: its answer is one error, `query_position_needs_platform` (`QueryRequest::validate` says so before the call).

Positions are 1-based lines and columns, in Unicode code points, `end_column` exclusive. A missing engine raises `opentide.analysis.EngineUnavailableError`, never a silent pass.

## On a tenant

`Connection.validate_query` runs the query on one tenant, as `opentide validate query --live` does for a rule's queries: see [tenant operations](./workspace.md#tenant-operations). SentinelOne's S1QL is checked there only; CrowdStrike, HarfangLab and Sysdig have no tenant check and say so (`operation_unsupported`), never a fake pass.

<Callout type="info">
Four entry points — pick deliberately:

| Entry point | Behaviour |
|---|---|
| `opentide.analysis.check_query` | Offline, in-process, with the analysis engine |
| `Connection.validate_query` | Live vendor call. Needs a configured tenant |
| `opentide validate query` | Offline by default; `--live` calls the tenant |
| MCP `validate_query` | Offline by default; `live: true` calls the tenant |

See [`opentide validate query`](../cli/validate.md) and [MCP tools](../mcp/tools.md).
</Callout>

`run_validation`, `ValidationScope` and the registry's `rule.validate_query(platform)`, which this page documented before, are removed: see [Migration](./migration.md).

## Source

`src/opentide/analysis.py` (`check_query`), `src/opentide/sdk.py` (`Connection`), `crates/opentide-analysis/` (the engine).
