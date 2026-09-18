# KQL language design (Sentinel / Defender)

Context base for the OpenTide KQL engine. Inventory stays in the sibling
markdown files; this document is the **runtime model** the catalogs and LSP
must implement.

Citations:

- [Kusto query language](https://learn.microsoft.com/kusto/query/)
- [Tabular operators](https://learn.microsoft.com/kusto/query/tabular-operators)
- [Join operator](https://learn.microsoft.com/kusto/query/join-operator)
- [SecurityEvent](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityevent)
- [SigninLogs](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs)
- [DeviceProcessEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefileevents-table)
- [Advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)

## Layers

| Layer | Source of truth | Runtime |
| --- | --- | --- |
| Names (operators, functions, types, plugins, tables) | `catalogs/kql/core/*.toml`, `catalogs/kql/{sentinel,defender}/tables.toml` | hover / completions / highlight overlay |
| **Columns** | `catalogs/kql/{sentinel,defender}/columns.toml` | hover on `EventID`; completions after `\| where` / `project` / `by` |
| **Operator options** | `catalogs/kql/core/operator-options.toml` | `join kind=`, `union kind=`, `parse kind=`; signature help |
| Grammar | `grammars/tree-sitter-opentide-kql` | parse / injection |
| HighlightSpec | `highlights/spec.toml` | capture names only (no column names) |

Control commands (`.show`, `.create`, …) remain **unsupported** in detections
(`kql_control_command_unsupported`). SQL is out of scope.

## Profiles

| Profile | When | Time column | Tables |
| --- | --- | --- | --- |
| `sentinel` | `configurations.sentinel.query` or `.kql` default | `TimeGenerated` | Sentinel + streamed Defender tables |
| `defender` | `configurations.defender_for_endpoint.query` | `Timestamp` | Advanced hunting schema |
| `core` | unit tests / no workspace | none | operators + functions only |

A query may mention a table from the active profile. Column lookup prefers
tables that appear as identifiers in the current source, then falls back to
any catalog column of that name.

## Column model

Each row in `columns.toml`:

```toml
[[columns]]
table = "SecurityEvent"
profile = "sentinel"
name = "EventID"
type = "int"
docs = "Windows event identifier (e.g. 4688 process creation)."
citation = "https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityevent"
```

Hover on a table name lists a **column digest** (name + type), not just the
table blurb. Hover on a column shows type, table, and docs.

Completions after `| where `, `| project `, `| extend `, `| summarize … by `,
`| distinct `, `| sort by ` offer columns for tables referenced in the query.

## Operator options (signature help)

`join` is the primary option schema:

```
join kind=Kind [hint.strategy=Strategy] RightTable on Predicate
```

`Kind` ∈ `inner` `innerunique` `leftouter` `rightouter` `fullouter`
`leftanti` `anti` `rightanti` `leftsemi` `rightsemi`.

Other option-bearing operators (see `operator-options.toml`): `union kind=`,
`parse kind=`, `lookup kind=`, `make-series`, `mv-expand`, `evaluate`.

Signature help triggers on `(` for functions (`ago(`, `datetime(`, `dynamic(`)
and on `join ` / `kind=` for tabular options.

`dynamic([...])` is a **type constructor** (HighlightSpec `type`), not a
user function.

## Detection policy (diagnostics, not rewrite)

| Pattern | Sentinel analytics | Defender custom / NRT |
| --- | --- | --- |
| `search *` / `union *` | illegal | illegal |
| `join` / `union` / `externaldata` | allowed | **banned in NRT** |
| Comments | allowed | banned in NRT |
| Output columns | n/a | `Timestamp`/`TimeGenerated` + `DeviceId`/`ReportId` (see defender-tables.md) |

The engine does **not** rewrite authored KQL.

## Highlight overlay

Tree-sitter paints operators / tables / functions. The engine then remaps:

- catalog functions / plugins → `function.builtin`
- known columns (when not already keyword/function/type) → `property`
- join/union kinds → `keyword`
- `dynamic` / `datatable` / `timespan` constructors → `type`

## Related

- [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md) — punch list
- [sentinel-tables.md](sentinel-tables.md) / [defender-tables.md](defender-tables.md)
- [operators.md](operators.md)
