# KQL tabular operators

Tabular operators consume a table (from the pipe or as a source) and produce a table. Index hubs:

- [KQL overview](https://learn.microsoft.com/kusto/query/)
- [KQL quick reference](https://learn.microsoft.com/kusto/query/kql-quick-reference)
- [Tabular expression statements](https://learn.microsoft.com/kusto/query/tabular-expression-statements)

**Detection column** uses the [legend in README](README.md#detection-validity-legend).

Sentinel scheduled analytics extra rules: no `search *`, no `union *`, max 10,000 characters, no `adx()`. [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview)

Defender Continuous (NRT) extra rules: one table; no `join` / `union` / `externaldata`; no comments. [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

Azure Monitor does not support ADX-only plugins (`python`, `sql_request`, …) or `cluster()`/`database()`. [Log query overview](https://learn.microsoft.com/azure/azure-monitor/logs/log-query-overview)

---

## Filter, search, sample, limit

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `where` | `filter` | Filter | Keep rows whose predicate is true. Null comparisons are false. | [where](https://learn.microsoft.com/kusto/query/where-operator) | **Yes** |
| `search` | — | Search | Full-text search across columns/tables. Optional `kind=default\|case_insensitive`, `in (tables)`, `*` predicate. | [search](https://learn.microsoft.com/kusto/query/search-operator) | **Restricted** — forbidden as `search *` in Sentinel analytics; expensive; NRT-no if multi-table |
| `find` | — | Search | Find rows matching a predicate across a set of tables; adds `source_` column. | [find](https://learn.microsoft.com/kusto/query/find-operator) | **Restricted** — hunting-friendly; avoid unbounded `find in (*)` in detections; NRT-no (multi-table) |
| `take` | `limit` | Limit | Return the first *N* rows (not a statistical sample; order undefined unless `sort`/`serialize` first). | [take](https://learn.microsoft.com/kusto/query/take-operator) | **Yes** (use for hunting; detections should not rely on arbitrary first-N) |
| `top` | — | Limit + sort | `top N by expr [asc\|desc] [nulls first\|last]` — sort then take. | [top](https://learn.microsoft.com/kusto/query/top-operator) | **Yes** |
| `top-hitters` | — | Approximate frequent | Approximate most frequent values of an expression (performance over fairness). | [top-hitters](https://learn.microsoft.com/kusto/query/top-hitters-operator) | **Hunting** / rare in detections |
| `top-nested` | — | Hierarchical top | Nested “top N of X by agg, top M of Y by agg” hierarchies. | [top-nested](https://learn.microsoft.com/kusto/query/top-nested-operator) | **Hunting** |
| `sample` | — | Sample | Random sample of *N* rows (biased; not statistically fair). | [sample](https://learn.microsoft.com/kusto/query/sample-operator) | **Hunting** (non-deterministic detections are a bad idea) |
| `sample-distinct` | — | Sample | Up to *N* distinct values of one column (biased). | [sample-distinct](https://learn.microsoft.com/kusto/query/sample-distinct-operator) | **Hunting** |

---

## Project, extend, distinct

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `project` | — | Project | Select, rename, and compute columns; drops unspecified columns. | [project](https://learn.microsoft.com/kusto/query/project-operator) | **Yes** — required to keep `Timestamp`/`DeviceId`/`ReportId` |
| `project-away` | — | Project | Drop named columns; keep the rest. | [project-away](https://learn.microsoft.com/kusto/query/project-away-operator) | **Yes** |
| `project-keep` | — | Project | Keep columns matching wildcards; drop the rest. | [project-keep](https://learn.microsoft.com/kusto/query/project-keep-operator) | **Yes** |
| `project-rename` | — | Project | Rename columns; keep others. | [project-rename](https://learn.microsoft.com/kusto/query/project-rename-operator) | **Yes** |
| `project-reorder` | — | Project | Reorder columns (`asc`, `desc`, wildcards). | [project-reorder](https://learn.microsoft.com/kusto/query/project-reorder-operator) | **Yes** |
| `extend` | — | Project | Append calculated columns; original columns remain. | [extend](https://learn.microsoft.com/kusto/query/extend-operator) | **Yes** |
| `distinct` | — | Dedup | Distinct combinations of the listed columns (equivalent to `summarize by …` with no aggregates). | [distinct](https://learn.microsoft.com/kusto/query/distinct-operator) | **Yes** |

---

## Aggregate and series

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `summarize` | — | Aggregate | Group by expressions; compute aggregation functions. | [summarize](https://learn.microsoft.com/kusto/query/summarize-operator) | **Yes** |
| `count` | — | Aggregate | Shorthand for `summarize count()`. | [count](https://learn.microsoft.com/kusto/query/count-operator) | **Yes** (poor sole alert payload) |
| `make-series` | — | Time series | Build arrays of aggregated values along a timeline (`from`/`to`/`step`, `by`). | [make-series](https://learn.microsoft.com/kusto/query/make-series-operator) | **Hunting** / advanced scheduled (anomaly); NRT-no typical |
| `serialize` | — | Windowing | Order rows and enable window functions (`next`, `prev`, `row_number`, `row_cumsum`). Implied by `sort`/`top`. | [serialize](https://learn.microsoft.com/kusto/query/serialize-operator) | **Yes** (ordered detections, sequence) |
| `scan` | — | Sequence | Stateful scan of ordered rows (declare/step/output) for sequences and sessionization. | [scan](https://learn.microsoft.com/kusto/query/scan-operator) | **Hunting** / advanced scheduled; needs `serialize` |

---

## Join, union, lookup

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `join` | — | Combine | Join two tabular expressions. Kinds: `innerunique` (default), `inner`, `leftouter`, `rightouter`, `fullouter`, `leftanti`/`leftantisemi`/`anti`, `rightanti`/`rightantisemi`, `leftsemi`, `rightsemi`. `on` columns or `$left.a == $right.b`. Hints: `hint.strategy=broadcast\|shuffle`. | [join](https://learn.microsoft.com/kusto/query/join-operator) | **Yes** scheduled; **NRT-no** |
| `union` | — | Combine | Concatenate rows from tables/expressions. Flags: `kind=inner\|outer` (schema), `withsource=Col`, `isfuzzy=true`. | [union](https://learn.microsoft.com/kusto/query/union-operator) | **Restricted** — `union *` banned in Sentinel analytics; **NRT-no** |
| `lookup` | — | Combine | Fact-table left lookup of a small dimension table (`kind=leftouter\|inner`). Simpler/faster than `join` for enrichments. | [lookup](https://learn.microsoft.com/kusto/query/lookup-operator) | **Yes** scheduled; treat as join for NRT (avoid) |

Join kinds citation details: [join](https://learn.microsoft.com/kusto/query/join-operator). Cross-cluster join is **AM-no**. [Log query overview](https://learn.microsoft.com/azure/azure-monitor/logs/log-query-overview)

---

## Parse and expand

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `parse` | — | Parse | Parse a string into typed columns (`kind=simple\|regex\|relaxed`, `flags=`). | [parse](https://learn.microsoft.com/kusto/query/parse-operator) | **Yes** |
| `parse-where` | — | Parse + filter | Like `parse` but **drops** rows that fail to match. | [parse-where](https://learn.microsoft.com/kusto/query/parse-where-operator) | **Yes** |
| `parse-kv` | — | Parse | Extract key/value pairs (delimiters or regex) into typed columns. | [parse-kv](https://learn.microsoft.com/kusto/query/parse-kv-operator) | **Yes** |
| `mv-expand` | `mvexpand` (deprecated spelling) | Expand | Expand dynamic arrays/bags to rows (`bagexpansion`, `with_itemindex`, `limit`). Azure Monitor caps expansion (historically 2,000). | [mv-expand](https://learn.microsoft.com/kusto/query/mv-expand-operator) | **Yes** |
| `mv-apply` | — | Expand | Expand arrays and run a **subquery per element**; union results. Generalization of `mv-expand`. | [mv-apply](https://learn.microsoft.com/kusto/query/mv-apply-operator) | **Yes** scheduled; some cross-service paths unsupported (`smv-apply` typo in older docs) |

---

## Sort

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `sort` | `order` | Sort | `sort by expr [asc\|desc] [nulls first\|last] [, …]`. Implies serialization. | [sort](https://learn.microsoft.com/kusto/query/sort-operator) | **Yes** |

---

## Sources (no pipe input)

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `print` | — | Source | One row of scalar expressions. | [print](https://learn.microsoft.com/kusto/query/print-operator) | **Hunting** |
| `datatable` | — | Source | Inline literal table. | [datatable](https://learn.microsoft.com/kusto/query/datatable-operator) | **Yes** (IOC lists) |
| `range` | — | Source | Arithmetic series table: `range col from a to b step s`. | [range](https://learn.microsoft.com/kusto/query/range-operator) | **Hunting** / scaffolding |
| `externaldata` | — | Source | Read a schema from an **external** URI (blob/HTTP) into a table. | [externaldata](https://learn.microsoft.com/kusto/query/externaldata-operator) | **Restricted** — **NRT-no**; often blocked/unreliable in Sentinel analytics (egress, auth); prefer watchlists |

Azure Monitor exclusive **functions** used as sources (not operators): `workspace()`, `app()`, `resource()`. [Log query overview](https://learn.microsoft.com/azure/azure-monitor/logs/log-query-overview). `workspace()` is **not** supported in Defender custom detections. [Use Sentinel functions in Defender](https://learn.microsoft.com/defender-xdr/advanced-hunting-defender-use-custom-rules)

---

## Invoke, evaluate, schema, name

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `invoke` | — | Function | `T \| invoke UserFunction(args)` — run a tabular UDF on the pipe. | [invoke](https://learn.microsoft.com/kusto/query/invoke-operator) | **Yes** |
| `evaluate` | — | Plugin | Invoke a service plugin (`bag_unpack`, `autocluster`, …). Output schema may be data-dependent. | [evaluate](https://learn.microsoft.com/kusto/query/evaluate-operator) | **Restricted** — `bag_unpack`/`pivot` common; Python/SQL plugins **AM-no**; Sentinel `bag_unpack` needs `column_ifexists` when projecting optional fields |
| `getschema` | — | Metadata | One row per input column (`ColumnName`, `DataType`, `ColumnType`). | [getschema](https://learn.microsoft.com/kusto/query/getschema-operator) | **Hunting** |
| `as` | — | Name | Bind a name to the current tabular result (`hint.materialized=true` wraps `materialize()`). Used by `union withsource`, `find`, `search`, `partition` (legacy). | [as](https://learn.microsoft.com/kusto/query/as-operator) | **Yes** |

`materialize()` is a **function**, not a pipe operator: `let X = materialize(T | where …);`. [materialize](https://learn.microsoft.com/kusto/query/materialize-function) — **Yes** in scheduled queries.

---

## Partition, fork, facet, consume, reduce

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `partition` | — | Subquery | Run a subquery per distinct value (`by Col`, strategies `native`/`shuffle`/`legacy`). Subquery must return **one** table. `fork` not allowed inside. | [partition](https://learn.microsoft.com/kusto/query/partition-operator) | **Hunting** / advanced scheduled |
| `fork` | — | Multi-result | Run several subqueries in parallel; **multiple result tables**. Supported inner ops limited (`where`, `project*`, `summarize`, `top`, `sort`, `mv-expand`, `reduce`, …). | [fork](https://learn.microsoft.com/kusto/query/fork-operator) | **Hunting** — detections need a **single** result set |
| `facet` | — | Multi-result | One summary table per listed column (+ optional `with` pipe). Results cannot be piped further. | [facet](https://learn.microsoft.com/kusto/query/facet-operator) | **Hunting** |
| `consume` | — | Sink | Consume (discard) the data; returns completion stats. | [consume](https://learn.microsoft.com/kusto/query/consume-operator) | **No** |
| `reduce` | — | Cluster strings | Group similar string values (`reduce by col`) for pattern hunting. | [reduce](https://learn.microsoft.com/kusto/query/reduce-operator) | **Hunting** |

---

## Graph operators

Newer graph operators (Sentinel/Azure Monitor support is indicated on each Learn page as Fabric / ADX / Azure Monitor / Sentinel). Treat as **Hunting** unless the rule is proven on the target workspace.

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `make-graph` | — | Graph | Build a graph from edges (`source`/`target`) and optional node tables; `partitioned-by` for per-tenant graphs. | [make-graph](https://learn.microsoft.com/kusto/query/make-graph-operator) | **Hunting** |
| `graph-match` | — | Graph | Pattern-match nodes/edges (`where` constraints, `project`). Requires `make-graph`. | [graph-match](https://learn.microsoft.com/kusto/query/graph-match-operator) | **Hunting** |
| `graph-shortest-paths` | — | Graph | Shortest paths in a graph source. | [graph-shortest-paths](https://learn.microsoft.com/kusto/query/graph-shortest-paths-operator) | **Hunting** |
| `graph-to-table` | — | Graph | Emit nodes/edges of a graph as tables. | [graph-to-table](https://learn.microsoft.com/kusto/query/graph-to-table-operator) | **Hunting** |
| `graph-mark-components` | — | Graph | Mark connected components on a graph. | [graph-mark-components](https://learn.microsoft.com/kusto/query/graph-mark-components-operator) | **Hunting** |

---

## Visualization

| Name | Aliases | Category | Short docs | Citation | Detections |
| --- | --- | --- | --- | --- | --- |
| `render` | — | Visualize | Render as `table`, `timechart`, `barchart`, `piechart`, `areachart`, `scatterchart`, `pivotchart`, … | [render](https://learn.microsoft.com/kusto/query/render-operator) | **No** — `not_valid_in_detections` |

---

## `evaluate` plugins

Citation: [evaluate operator](https://learn.microsoft.com/kusto/query/evaluate-operator)

Plugins invoked as `T | evaluate PluginName(args)`. Azure Monitor / Sentinel support is **plugin-specific**. Python, R, `sql_request`, `mysql_request`, `cosmosdb_sql_request`, `azure_digital_twins_query_request` are **AM-no** or require special cluster config — **not** for detections.

| Plugin | Short docs | Citation | Detections |
| --- | --- | --- | --- |
| `bag_unpack` | Expand a `dynamic` property bag into columns. Prefer explicit output schema. | [bag_unpack](https://learn.microsoft.com/kusto/query/bag-unpack-plugin) | **Restricted** — common in Sentinel; project with `column_ifexists("field","")` |
| `pivot` | Rotate unique values of a column into columns + aggregate. | [pivot](https://learn.microsoft.com/kusto/query/pivot-plugin) | **Hunting** |
| `autocluster` | Find common discrete patterns (failure analysis). | [autocluster](https://learn.microsoft.com/kusto/query/autocluster-plugin) | **Hunting** |
| `basket` | Frequent itemsets / association patterns. | [basket](https://learn.microsoft.com/kusto/query/basket-plugin) | **Hunting** |
| `diffpatterns` | Contrast patterns between two datasets. | [diffpatterns](https://learn.microsoft.com/kusto/query/diffpatterns-plugin) | **Hunting** |
| `diffpatterns_text` | Text variant of diffpatterns. | [diffpatterns-text](https://learn.microsoft.com/kusto/query/diffpatterns-text-plugin) | **Hunting** |
| `sequence_detect` | Detect sequences of events. | [sequence-detect](https://learn.microsoft.com/kusto/query/sequence-detect-plugin) | **Hunting** |
| `narrow` | Unpivot columns to name/value rows. | [narrow](https://learn.microsoft.com/kusto/query/narrow-plugin) | **Hunting** |
| `preview` | Preview plugin output. | [preview](https://learn.microsoft.com/kusto/query/preview-plugin) | **Hunting** |
| `rolling_percentile` | Rolling percentile over a window. | [rolling-percentile](https://learn.microsoft.com/kusto/query/rolling-percentile-plugin) | **Hunting** |
| `rows_near` | Rows near matching rows. | [rows-near](https://learn.microsoft.com/kusto/query/rows-near-plugin) | **Hunting** |
| `dcount_intersect` | Intersection of distinct counts / HLL. | [dcount-intersect](https://learn.microsoft.com/kusto/query/dcount-intersect-plugin) | **Hunting** |
| `ipv4_lookup` | Lookup IPs in a CIDR dimension table. | [ipv4-lookup](https://learn.microsoft.com/kusto/query/ipv4-lookup-plugin) | **Restricted** / hunting |
| `ipv6_lookup` | IPv6 variant. | [ipv6-lookup](https://learn.microsoft.com/kusto/query/ipv6-lookup-plugin) | **Restricted** / hunting |
| `schema_merge` | Merge schemas. | [schema-merge](https://learn.microsoft.com/kusto/query/schema-merge-plugin) | **Hunting** |
| `infer_storage_schema` | Infer schema from storage. | [infer-storage-schema](https://learn.microsoft.com/kusto/query/infer-storage-schema-plugin) | **AM-no** / not detections |
| `sql_request` | Query an external SQL database. | [sql-request](https://learn.microsoft.com/kusto/query/sql-request-plugin) | **AM-no** |
| `mysql_request` | Query MySQL. | [mysql-request](https://learn.microsoft.com/kusto/query/mysql-request-plugin) | **AM-no** |
| `cosmosdb_sql_request` | Query Cosmos DB. | [cosmosdb plugin](https://learn.microsoft.com/kusto/query/cosmosdb-plugin) | **AM-no** |
| `azure_digital_twins_query_request` | Query ADT. | [ADT plugin](https://learn.microsoft.com/kusto/query/azure-digital-twins-query-request-plugin) | **AM-no** |
| `python` / `R` | Sandboxed script plugins. | [python](https://learn.microsoft.com/kusto/query/python-plugin), [R](https://learn.microsoft.com/kusto/query/r-plugin) | **AM-no** |

`http_request` / `http_request_post` plugins exist in ADX for egress HTTP — **not** for Sentinel/Defender detections.

---

## Unsupported: control / management commands

**Not query operators.** List only as unsupported in detections. They begin with `.`.

Citation: [Management commands overview](https://learn.microsoft.com/kusto/management/), [KQL overview](https://learn.microsoft.com/kusto/query/)

| Command | Purpose | Detections |
| --- | --- | --- |
| `.show tables` / `.show table T` / `.show databases` / `.show functions` | Metadata | **No** |
| `.show table T schema` / `.show database schema` | Schema | **No** |
| `.create table` / `.create-merge table` / `.alter table` / `.drop table` | DDL | **No** |
| `.create function` / `.alter function` / `.drop function` | Stored functions | **No** |
| `.ingest` / `.set` / `.append` / `.set-or-append` / `.set-or-replace` | Ingest | **No** |
| `.clear table` / `.drop extents` | Data mutation | **No** |
| `.execute database script` | Batch management | **No** |

Use `getschema` (query) or the in-portal schema browser instead of `.show`.

---

## Azure Monitor–only query sources (functions)

| Name | Docs | Citation | Detections |
| --- | --- | --- | --- |
| `workspace("…")` | Query another Log Analytics workspace | [Cross-workspace](https://learn.microsoft.com/azure/azure-monitor/logs/cross-workspace-query) | Sentinel analytics **Restricted** (limits); Defender custom detections **No** |
| `app("…")` | Query Application Insights | same | Uncommon in Sentinel detections |
| `resource("…")` | Correlate Azure Resource Graph | same | Uncommon |
| `adx("…")` | Proxy to Azure Data Explorer | [ADX proxy](https://learn.microsoft.com/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy) | **No** in Sentinel analytics rules; hunting-only in some Defender experiences |

---

## Operator count

| Group | Count (this page) |
| --- | --- |
| Tabular operators (including aliases documented as peers: `filter`, `limit`, `order`) | **58** unique names (`where`/`filter`, `take`/`limit`, `sort`/`order` counted once each as primary + alias) |
| Distinct primary operators | **55** |
| Evaluate plugins listed | **21** |
| Control command classes (unsupported) | **7** families |

Aliases counted in catalogs: `filter` (=`where`), `limit` (=`take`), `order` (=`sort`), `mvexpand` (=`mv-expand`).
