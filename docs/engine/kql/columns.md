# Tables and columns

What the engine knows about the datasets a KQL query reads, and what it reports. Epic [#110](https://github.com/opentidehq/language-server/issues/110).

## Tiers

| Tier | What | Check | Severity |
| --- | --- | --- | --- |
| 1. Documented schema | Azure Monitor Logs tables, Defender XDR and advanced hunting tables, ASIM parsers | name, columns, types | error on a near miss of a documented column (`kql_unknown_column`, with the column it misspells) or on an operator Kusto does not define for a column's type (`kql_type_mismatch`) |
| 2. Declared in `visibility.toml` | the `name` of a `sentinel` or `defender_for_endpoint` log source, with its `columns` when it lists them | name; with `columns`, columns and types as tier 1 | none for the name; with `columns`, as tier 1 |
| 3. Not declared | a catalog table the workspace does not declare | name | `kql_table_not_declared` (warning), once the workspace declares tables for the platform; nothing otherwise |
| 4. Neither | a name neither the catalog nor `visibility.toml` knows | name | `kql_unknown_table` at the profile's severity, declarations or not: a warning under `sentinel`, an error under `defender_for_endpoint`; once the workspace declares tables for the platform, its message names the declaration |

- An unknown table is never an error under `sentinel`: the engine cannot see the workspace. Under `defender_for_endpoint`, advanced hunting is a closed schema and an unknown table stays an error.
- Declarations are per platform. A Splunk sourcetype never makes a Sentinel table known.
- Opt-in: a catalog table that is not declared warns only when the workspace declares at least one table for that platform. An unknown name is reported either way (the spec's precedence, [#147](https://github.com/opentidehq/language-server/issues/147)).
- Declared columns (`[logsources.columns]`, keyed by the column name as the platform spells it, each `{ type = "<KQL scalar type>", description = "..." }`) make a declared table a documented one: a near miss of one is `kql_unknown_column`, an operator its type lacks `kql_type_mismatch`, and hover and completion show its type and description. On a table the catalog knows they extend its columns; one with a catalog column's name replaces that column's type (and its description, when it has one). A table declared without `columns` is known by name only.
- Columns on a pattern (`Vendor*_CL`) apply to every table it matches: a catalog table, a declared one, or one only the query names. When several log sources give a table columns (an exact entry and a pattern, or two patterns), their columns merge; on a column both declare, the exact entry wins over a pattern, and an earlier pattern over a later one. The same rule applies to Elastic fields declared on index patterns and to Splunk fields declared on sourcetype patterns.
- `union isfuzzy=true` reads whichever legs exist, so its legs are not checked.
- Source names: every name a query reads from (a pipeline's source, a `union` leg, a `join` or `lookup` right side) is checked, except `let` bindings, tabular parameters, functions the engine knows (`_GetWatchlist`) and ASIM parsers (and, under `sentinel`, names in their form: `_Im_*`, `_ASim_*`, `im*`, `vim*`, `ASim*`). Without declarations for the platform, a name that starts with a lower-case letter and does not end in `_CL` is not checked, as it may be a workspace function; once the workspace declares tables, every name is checked whatever its case, and a workspace function is declared like a table ([#149](https://github.com/opentidehq/language-server/issues/149)).

The engine reads `.opentide/configurations/visibility.toml` itself (`DeclaredDatasets::from_visibility`). The language server reads it at start-up and again whenever it changes, in the editor (before it is saved) or on disk, and checks every open document again; `opentide validate` and `opentide tui` pass the file to the engine (`Catalog.visibility`, `install_visibility`). A log source's `name` is its table; the plural `tables = [...]` lists of opentide 0.20.0 are not part of the format and declare nothing (`opentide migrate visibility` rewrites them). A file that starts with a UTF-8 byte-order mark parses. The code action on `kql_table_not_declared` (and on a `kql_unknown_table` that names the declaration) appends a new `[[logsources]]` entry with `name`, an empty `description` and `system` to `.opentide/configurations/visibility.toml`; it never edits an existing entry.

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
- Patterns: `project-away`, `project-keep` and `project-reorder` take column patterns (`*`, `User*`, `*Id`), a case-sensitive glob over the input columns, never a column reference. `project-away` removes every column a pattern matches and `project-keep` every column no name or pattern matches; `project-keep` with a pattern leaves the columns as sure as they were, since it may keep undocumented ones. `project-reorder` keeps every column.
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
