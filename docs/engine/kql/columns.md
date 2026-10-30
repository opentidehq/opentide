# Tables and columns

What the engine knows about the datasets a KQL query reads, and what it reports. Epic [#110](https://github.com/opentidehq/language-server/issues/110).

## Three tiers

| Tier | What | Check | Severity |
| --- | --- | --- | --- |
| 1. Documented schema | Azure Monitor Logs tables, Defender XDR and advanced hunting tables, ASIM parsers | name, columns, types | error on a near miss of a documented column (`kql_unknown_column`, with the column it misspells) or on an operator Kusto does not define for a column's type (`kql_type_mismatch`) |
| 2. Declared in `visibility.toml` | the `tables` of a `sentinel` or `defender_for_endpoint` log source | name | none |
| 3. Neither | any other name | name | warning: `kql_unknown_table` (`sentinel`), or `kql_table_not_declared` once the workspace declares tables for the platform |

- An unknown table is never an error under `sentinel`: the engine cannot see the workspace. Under `defender_for_endpoint`, advanced hunting is a closed schema and an unknown table stays an error.
- Declarations are per platform. A Splunk index never makes a Sentinel table known.
- Opt-in: a built-in table that is not declared warns only when the workspace declares at least one table for that platform.
- `union isfuzzy=true` reads whichever legs exist, so its legs are not checked.

The engine reads `.opentide/configurations/visibility.toml` itself (`DeclaredDatasets::from_visibility`). The language server reads it at start-up and again whenever it changes, in the editor (before it is saved) or on disk, and checks every open document again; `opentide validate` and `opentide tui` pass the file to the engine (`Catalog.visibility`, `install_visibility`). The code action on `kql_table_not_declared` (and on the `kql_unknown_table` warning) adds the table to the `tables` of the first log source of the platform in `.opentide/configurations/visibility.toml`, or appends a log source when none fits.

## Catalogs

| File | Source | Generator |
| --- | --- | --- |
| `catalogs/kql/azure-monitor/tables.toml` | [Azure Monitor Logs table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/tables-category) (MicrosoftDocs/azure-monitor-docs, CC BY 4.0), plus the columns of Azure-Sentinel's KQL validation schemas (MIT) | `scripts/sync_azure_monitor_tables.py` |
| `catalogs/kql/asim/asim.toml` | [ASIM](https://learn.microsoft.com/azure/sentinel/normalization) schemas from `ASIM/dev/ASimTester/ASimTester.csv` and parsers from `Parsers/ASim*/Parsers/*.yaml` (Azure/Azure-Sentinel, MIT) | `scripts/sync_asim_schemas.py` |
| `catalogs/kql/{sentinel,defender}/` | hand-written tables and detection-critical columns with docs | — |

Both generators take a checkout (`--docs`, `--sentinel`) and have `--check`. Each column is a sub-table with named keys, one per line (`[[tables.columns]]` with `name`, `type` and `description`; `[[schemas.columns]]` with `name`, `type` and `class`), so a change to a column is a one-line diff. A column's `description` is the first sentence of the reference's Description cell, kept as Markdown; it is left out where the cell is empty and for the columns that come from the validation schemas. ASIM columns have no description: Azure-Sentinel has none in machine-readable form (`ASimTester.csv` has no description field; the descriptions are prose tables in the schema articles on Microsoft Learn). The hand-written columns are merged in and never removed; where a hand-written type disagrees with the reference, the column has no type and gets no type check. Every Log Analytics table also has the [standard columns](https://learn.microsoft.com/azure/azure-monitor/logs/log-standard-columns), and any `_CF` column (a data collection rule adds those). Advanced hunting tables have `Timestamp`.

ASIM parsers are known in every form: unifying `_Im_<Schema>` and `_ASim_<Schema>`, workspace `im<Schema>` and `ASim<Schema>`, source-specific `_Im_<Schema>_<Source>` and `vim<Schema><Source>`, and the ingest-time `ASim*Logs` tables. Their filtering parameters (`starttime`, `dstportnumber`, ...) get signature help and parse as named arguments (`_Im_NetworkSession(starttime=ago(1d))`). Hover shows the schema and parameters.

## Columns through a query

`crates/opentide-kql/src/schema.rs` follows each tabular expression and knows, at every operator, the columns, their types and the operator that made each one:

- Sources: a catalog table, an ASIM parser, a `let`-bound tabular value or tabular function (its parameters bound), `materialize`, `datatable`, `print`, `union` (with `withsource=`; a name with two types becomes `Name_string`, `Name_long`).
- Operators: `project` and its family (`-away`, `-keep`, `-rename`, `-reorder`), `extend`, `summarize` (by columns first; unnamed aggregates named as Kusto names them: `count_`, `dcount_X`, `set_X`, `list_X`, `take_any(X)` keeps `X`, `arg_max(T, *)` keeps every column, `L = arg_max(T, *)` names `T` `L`), `distinct` (a named expression, `distinct B = tolower(A)`, is its output column; `distinct *` keeps every column), `count`, `join` (the kind decides which side survives; a repeated name gets `1`, `2`, ...), `lookup`, `union`, `mv-expand` (with `with_itemindex` and `to typeof()`), `mv-apply`, `parse` and `parse-where`.
- Names: a quoted identifier (`['Display Name']`, `["c"]`) is the column it quotes, wherever a column is read or named.
- Open: an unknown source, `evaluate`, `parse-kv`, `invoke` and other keyword operators, an unnamed expression in `extend`, `project`, `distinct` or `by` (Kusto names it `Column1`), the deprecated `argmax`/`argmin` (`max_T_Col`) and `percentiles`. Nothing below an open point gets a column diagnostic.

How sure the pass is decides what it reports:

| Columns | Reported |
| --- | --- |
| documented source (a table of the reference, an ASIM parser, an advanced hunting table) | only a near miss of a documented column, as an error with the column it misspells. A table gains columns before the reference lists them (Microsoft's own validation skips rules for that), and ASIM source parsers add their own. |
| after `project`, `summarize`, `distinct`, `count`, or a `datatable` | any name that is not a column: the query itself says which columns exist |
| a column `project-away`, `project-rename` or `project-keep` removed | always |
| open | nothing |

A query that does not parse gets no column diagnostic. Hover on a column shows its type and the operator that made or renamed it; on a column of a source, its description from the table it comes from (in `union` and `join`, the table on its own side, not the first table the query names) and the table's Learn page, or for an ASIM column its class and schema with the schema's documentation link. Completion after `where`, `project` and the other column operators puts the description in each column's documentation. `perf.rs` asks the pass which columns a predicate reads and which operator made them: a `where` on a column an earlier `extend` makes, or that the source does not have (a `join` brought it in), is not `kql_where_not_first`; a pipeline that starts from a `let` is not a table reference; and a `let` that ends in `project`, `summarize` or `distinct`, or a `union` of such `let`s, counts as narrowed.

## Type checks

`kql_type_mismatch` reports only what Kusto rejects, each rule checked against Microsoft's Kusto.Language with the catalog's schemas. The KQL oracle (`scripts/oracles/README.md`) keeps it so: every column or type error the engine reports on the corpus and on `testdata/conformance/columns/` must be one Kusto.Language reports too.

- a string operator (`has`, `contains`, `startswith`, `endswith`, `hasprefix`, `hassuffix` and their `!`/`_cs` forms, `=~`, `!~`, `matches regex`) or `has_any`, `has_all`, `in~` on a numeric, `datetime`, `timespan` or `bool` column;
- `between` on a `string`, `bool` or `guid` column;
- `<`, `>`, `<=`, `>=` between a `string`, `guid`, `datetime` or `timespan` column and a string or number literal, or between a numeric column and a string literal.

Equality is not a type check: Kusto accepts `EventID == "4688"`.

## How it was measured

Against the analytics rules and hunting queries of Azure/Azure-Sentinel (5,130 queries, which Microsoft's CI validates against its table schemas): no `kql_unknown_column` or `kql_type_mismatch`. A one-letter typo injected into the first `where` column of 1,028 of those queries is caught in 904, each with the right suggestion; the rest are queries the grammar does not parse yet.
