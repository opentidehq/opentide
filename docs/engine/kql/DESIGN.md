# KQL language design (Sentinel / Defender)

Context base for the opentide KQL engine. Inventory stays in the sibling
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

Signature help (`signature_help`) prefers the innermost open `(` call. An
ASIM parser shows its filter parameters. A catalog function uses its
`signature` string, or `{name}(…)` when it has none. An evaluate plugin
uses its `signature` only when one is set. If no call matches, the first
word after the last `|` uses the operator `signature` from `operators.toml`
(`join`, `where`, `parse`, …). The server's trigger characters are `(`,
`,`, `=` and `` ` ``.

`dynamic([...])` is a **type constructor** (HighlightSpec `type`), not a
user function.

Refresh function, operator, and plugin signatures from a checkout of
[MicrosoftDocs/dataexplorer-docs](https://github.com/MicrosoftDocs/dataexplorer-docs)
(`data-explorer/kusto/query`):

```bash
python3 scripts/sync_kql_learn_signatures.py --docs /path/to/dataexplorer-docs
python3 scripts/sync_kql_learn_signatures.py --docs /path/to/dataexplorer-docs --write
```

Without `--write` the script prints repaired, skipped, and suspicious rows
and leaves the TOML files alone. A row whose article cannot be read is
skipped and kept as-is, and a deprecated function is not touched.
`encode_base64` / `decode_base64` are not on the cited Learn page: the
script drops those rows and adds `base64_encodestring` /
`base64_decodestring` when they are missing, instead of copying a neighbor
signature. `column_names_of` and `project-by-names` are added when the
article exists and the catalog row does not.

## Slow-query warnings

`crates/opentide-kql/src/perf.rs` emits **warnings**. The query text is left
as authored. Every message cites
[Kusto query best practices](https://learn.microsoft.com/en-us/kusto/query/best-practices).
The same codes fire on a raw `.kql` file and inside every Tide block
analysed as KQL (the injection table in
[ARCHITECTURE.md](../ARCHITECTURE.md#injection-table)).

The first two rules read each pipeline through the column pass
([columns.md](columns.md)).

| Code | Fires when |
| --- | --- |
| `kql_where_not_first` | The pipeline starts from a table or an ASIM parser (a custom or unknown name counts; a `let` does not), its first operator is not `where` or `filter`, and the first `where` / `filter` in it reads no column an earlier operator makes. The range is that `where` / `filter`. `SecurityEvent \| where … \| extend …` and `SigninLogs \| extend Domain = … \| where Domain == …` are clean. |
| `kql_join_summarize_before_project` | `join` or `summarize` runs before any `project`, `project-keep` or `project-away`, **and** one of those comes later. `summarize` with no later project is clean, and so is a pipeline that starts from a `let` ending in `project`, `summarize` or `distinct`. `summarize arg_max(T, *)` / `arg_min(T, *)` needs every column and is never flagged. |
| `kql_unscoped_search` | `search` starts a statement, has a predicate, and has no `in (Table, …)` list. `search *` uses this code. `search in (SecurityEvent) "error"` and `SecurityEvent \| search "error"` are clean. |
| `kql_wildcard_table` | A `*` table starts a statement (`* \| take 1`), or a `*` is inside `search in (…)`. |
| `kql_unscoped_union` | `union` starts a statement or follows `\|`, and a `*` appears in its arguments outside parentheses (`union *`). |

Join cardinality and `hint.shufflekey` are omitted: the text does not say
which side is larger.

`kql_render_not_valid` is a warning too, but a separate rule: `render` is not
valid in a detection. The engine does not check Defender's required output
columns ([defender-tables.md](defender-tables.md)) or the Defender NRT bans
(`join`, `union`, `externaldata`, comments):
[IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md).

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
