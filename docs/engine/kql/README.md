# KQL inventory for Sentinel and Defender detections

This directory is a **query-language inventory** of Microsoft Kusto Query Language (KQL) as used in:

- Microsoft Sentinel scheduled analytics rules, NRT analytics rules, hunting queries
- Microsoft Defender XDR / Microsoft Defender for Endpoint (MDE) advanced hunting and custom detections

It is **not** a catalog of Azure Data Explorer management (control) commands. Control commands (`.show`, `.create`, `.alter`, `.drop`, `.ingest`, `.set`, …) are listed only as **unsupported** in detections — see [`control-commands.md`](control-commands.md).

## Scope

| In scope | Out of scope |
| --- | --- |
| Tabular query operators (`where`, `join`, `summarize`, …) | SQL |
| Scalar operators (`==`, `has`, `matches regex`, …) | Control / management commands as detections |
| Scalar functions (`ago()`, `parse_json()`, `ipv4_is_private()`, …) | ADX-only cluster administration |
| Aggregation functions used with `summarize` / `make-series` | Full list of every `_CL` partner table in the Sentinel marketplace |
| Scalar types | Python / R plugins as detection logic |
| Syntax: `let`, comments, strings, timespans, pipe pipelines | Visualization-only UX (workbooks charts) except noting `render` |
| Sentinel and Defender **tables used in detections/hunting** | CMPivot / Azure Resource Graph KQL dialects |
| Evaluate plugins (documented; catalog TBD) | — |

## How this inventory maps to repo catalogs

Machine-readable catalogs live under [`/workspace/catalogs/kql/`](../../catalogs/kql/):

| Catalog file | Count (2026-09-15) | This inventory |
| --- | --- | --- |
| `catalogs/kql/core/operators.toml` | 53 | [`operators.md`](operators.md) |
| `catalogs/kql/core/operators-scalar.toml` | 54 | [`operators-scalar.md`](operators-scalar.md) |
| `catalogs/kql/core/functions.toml` | 298 | [`scalar-functions.md`](scalar-functions.md) + [`aggregation-functions.md`](aggregation-functions.md) + [`scalar-functions-geo-series.md`](scalar-functions-geo-series.md) |
| `catalogs/kql/core/types.toml` | 10 | [`types.md`](types.md) |
| `catalogs/kql/sentinel/tables.toml` | 99 | [`sentinel-tables.md`](sentinel-tables.md) |
| `catalogs/kql/defender/tables.toml` | 65 | [`defender-tables.md`](defender-tables.md) |
| *(none yet)* | — | [`evaluate-plugins.md`](evaluate-plugins.md), [`syntax.md`](syntax.md), [`control-commands.md`](control-commands.md) |
| *(gap analysis)* | — | [`coverage-gap.md`](coverage-gap.md), [`IMPLEMENTATION-GAPS.md`](IMPLEMENTATION-GAPS.md) |

Core tabular ops, scalar ops, types, and common tables are largely cataloged. The largest remaining catalog hole is **111** Learn scalar functions (`series_*` / `geo_*` / `convert_*`) plus **evaluate plugins**. See [`coverage-gap.md`](coverage-gap.md).

## Detection validity legend

| Value | Meaning |
| --- | --- |
| **Yes** | Valid in Sentinel scheduled analytics and Defender custom detections, and in hunting |
| **Restricted** | Valid in scheduled detections with documented caveats (no `search *` / `union *`, length limits, NRT extra rules) |
| **Hunting** | Valid in Logs / advanced hunting; omit from detection rules (visualization, multi-result sets, metadata-only) |
| **NRT-no** | Banned or unsupported in Defender **Continuous (NRT)** custom detections |
| **AM-no** | Not supported in Azure Monitor / Sentinel / Defender (ADX / Fabric only) |
| **No** | Not a detection query construct (control commands, consume-all, etc.) |

## Platform notes (citations)

### Language is KQL, not SQL

Kusto queries are read-only tabular pipelines. Operators are sequenced with `|`. Query statements are `let`, tabular expressions, and (rarely) `set`. Management commands start with `.` and **cannot** be embedded in queries.

- [KQL overview](https://learn.microsoft.com/kusto/query/)
- [Queries](https://learn.microsoft.com/kusto/query/queries)
- [Tabular expression statements](https://learn.microsoft.com/kusto/query/tabular-expression-statements)
- [KQL quick reference](https://learn.microsoft.com/kusto/query/kql-quick-reference)

### Azure Monitor / Sentinel dialect

- **Not supported:** `cluster()`, `database()` cross-cluster patterns; Python / `sql_request` plugins; ADX `adx()` inside analytics rules.
- **Azure Monitor–only sources:** `workspace()`, `app()`, `resource()`.
- Sentinel scheduled analytics: query length limits; **must not** contain `search *` or `union *`.

Citations: [Log queries in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/log-query-overview), [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview), [Sentinel service limits](https://learn.microsoft.com/azure/sentinel/sentinel-service-limits).

### Defender XDR / MDE

Advanced hunting schema tables and custom detections: [query language](https://learn.microsoft.com/defender-xdr/advanced-hunting-query-language), [schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables), [custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules).

**Continuous (NRT)** custom detections: single table; no `join` / `union` / `externaldata`; no comments.

### `render`

Visualization only — `not_valid_in_detections` in the core catalog.

## File index

| File | Contents |
| --- | --- |
| [operators.md](operators.md) | Tabular operators |
| [operators-scalar.md](operators-scalar.md) | Scalar / string / numeric / logical / IPv4 / `between` |
| [evaluate-plugins.md](evaluate-plugins.md) | `evaluate` plugins |
| [control-commands.md](control-commands.md) | Unsupported `.` management commands |
| [scalar-functions.md](scalar-functions.md) | Scalar functions (core families) |
| [scalar-functions-geo-series.md](scalar-functions-geo-series.md) | Full `geo_*` / `series_*` / `convert_*` name lists |
| [aggregation-functions.md](aggregation-functions.md) | `summarize` / `make-series` aggregations |
| [types.md](types.md) | Scalar types |
| [syntax.md](syntax.md) | `let`, comments, strings, timespans, pipe |
| [sentinel-tables.md](sentinel-tables.md) | Common Sentinel / LA tables |
| [defender-tables.md](defender-tables.md) | Defender XDR schema tables |
| [coverage-gap.md](coverage-gap.md) | Catalog vs inventory (current counts) |
| [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md) | Punch-list: catalog / grammar / scm / LSP |

## Primary Microsoft Learn hubs

- [Kusto Query Language](https://learn.microsoft.com/kusto/query/)
- [Scalar functions](https://learn.microsoft.com/kusto/query/scalar-functions)
- [Aggregation functions](https://learn.microsoft.com/kusto/query/aggregation-functions)
- [String operators](https://learn.microsoft.com/kusto/query/datatypes-string-operators)
- [Numerical operators](https://learn.microsoft.com/kusto/query/numerical-operators)
- [Scalar data types](https://learn.microsoft.com/kusto/query/scalar-data-types/)
- [evaluate operator](https://learn.microsoft.com/kusto/query/evaluate-operator)
- [Management commands](https://learn.microsoft.com/kusto/management/)
- [Sentinel tables and connectors](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference)
- [Defender XDR schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
