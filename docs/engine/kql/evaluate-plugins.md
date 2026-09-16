# KQL `evaluate` plugins

Plugins are invoked as:

```kusto
T | evaluate PluginName([args…])
```

Citation: [evaluate operator](https://learn.microsoft.com/kusto/query/evaluate-operator)

They are **not** tabular operators. Azure Monitor / Sentinel / Defender support is **plugin-specific**. Anything that shells out to Python, R, or external SQL/HTTP is **AM-no** and must not appear in detections.

Detection legend: same as [`README.md`](README.md). Source list aligned with [`operators.md`](operators.md).

---

## Plugins used in hunting / occasional analytics

| Plugin | Short docs | Citation | Detections |
| --- | --- | --- | --- |
| `bag_unpack` | Expand a `dynamic` property bag into columns. Prefer an explicit output schema. | [bag_unpack](https://learn.microsoft.com/kusto/query/bag-unpack-plugin) | **Restricted** — common in Sentinel; project optional fields with `column_ifexists("field","")` |
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
| `dcount_intersect` | Intersection of distinct counts / HLL sketches. | [dcount-intersect](https://learn.microsoft.com/kusto/query/dcount-intersect-plugin) | **Hunting** |
| `ipv4_lookup` | Lookup IPs in a CIDR dimension table. | [ipv4-lookup](https://learn.microsoft.com/kusto/query/ipv4-lookup-plugin) | **Restricted** / hunting |
| `ipv6_lookup` | IPv6 variant of ipv4_lookup. | [ipv6-lookup](https://learn.microsoft.com/kusto/query/ipv6-lookup-plugin) | **Restricted** / hunting |
| `schema_merge` | Merge schemas. | [schema-merge](https://learn.microsoft.com/kusto/query/schema-merge-plugin) | **Hunting** |

---

## Plugins that are AM-no / not for detections

| Plugin | Short docs | Citation | Detections |
| --- | --- | --- | --- |
| `infer_storage_schema` | Infer schema from storage. | [infer-storage-schema](https://learn.microsoft.com/kusto/query/infer-storage-schema-plugin) | **AM-no** |
| `sql_request` | Query an external SQL database. | [sql-request](https://learn.microsoft.com/kusto/query/sql-request-plugin) | **AM-no** |
| `mysql_request` | Query MySQL. | [mysql-request](https://learn.microsoft.com/kusto/query/mysql-request-plugin) | **AM-no** |
| `cosmosdb_sql_request` | Query Cosmos DB. | [cosmosdb](https://learn.microsoft.com/kusto/query/cosmosdb-plugin) | **AM-no** |
| `azure_digital_twins_query_request` | Query Azure Digital Twins. | [ADT plugin](https://learn.microsoft.com/kusto/query/azure-digital-twins-query-request-plugin) | **AM-no** |
| `python` | Sandboxed Python plugin. | [python](https://learn.microsoft.com/kusto/query/python-plugin) | **AM-no** |
| `R` | Sandboxed R plugin. | [R](https://learn.microsoft.com/kusto/query/r-plugin) | **AM-no** |

ADX also documents HTTP egress plugins (`http_request` / `http_request_post`) — **not** for Sentinel/Defender detections.

---

## Catalog / LSP status

| Surface | Status |
| --- | --- |
| `catalogs/kql/**` | **No** `evaluate-plugins.toml` yet |
| Grammar | Parses `evaluate` via `keyword_operator`; plugin identifier is generic |
| Completions | Suggests `evaluate` as an operator; **does not** suggest plugin names |
| Hover | No plugin docs |
| Diagnostics | Does not validate plugin names or AM-no plugins |

Suggested catalog shape (future):

```toml
[[plugins]]
name = "bag_unpack"
docs = "Expand a dynamic property bag into columns"
warning = "use_column_ifexists_when_projecting"
citation = "https://learn.microsoft.com/kusto/query/bag-unpack-plugin"
```

---

## Count

| Group | Count |
| --- | --- |
| Hunting / restricted plugins listed | 15 |
| AM-no plugins listed | 7 |
| **Total named here** | **22** (`python` + `R` counted separately) |
