# KQL aggregation functions

Used with [`summarize`](https://learn.microsoft.com/kusto/query/summarize-operator) and [`make-series`](https://learn.microsoft.com/kusto/query/make-series-operator). They reduce a group of rows to scalar(s).

Index: [Aggregation functions](https://learn.microsoft.com/kusto/query/aggregation-functions)

Empty-group defaults ([summarize](https://learn.microsoft.com/kusto/query/summarize-operator)): `count`/`sum`/`dcount`/… → `0`; `make_list`/`make_set`/`make_bag` → `[]`; others → `null`.

Detection validity: **Yes** for scheduled Sentinel analytics and Defender custom detections unless noted. `arg_max`/`arg_min` are the standard way to keep `Timestamp`/`ReportId` when aggregating custom detections. [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

Deprecated aliases still seen in old hunting queries: `argmax()` → `arg_max()`, `argmin()` → `arg_min()`, `makeset()` → `make_set()`, `makelist()` → `make_list()`, `any()` → `take_any()`.

## Binary

| Function | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `binary_all_and` | `binary_all_and(expr)` | Bitwise AND of the group | [binary_all_and](https://learn.microsoft.com/kusto/query/binary-all-and-aggregation-function) |
| `binary_all_or` | `binary_all_or(expr)` | Bitwise OR of the group | [binary_all_or](https://learn.microsoft.com/kusto/query/binary-all-or-aggregation-function) |
| `binary_all_xor` | `binary_all_xor(expr)` | Bitwise XOR of the group | [binary_all_xor](https://learn.microsoft.com/kusto/query/binary-all-xor-aggregation-function) |

## Dynamic / collection

| Function | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `buildschema` | `buildschema(dynamicExpr)` | Minimal schema admitting all dynamic values | [buildschema](https://learn.microsoft.com/kusto/query/buildschema-aggregation-function) |
| `make_bag` | `make_bag(dynamicExpr [, maxSize])` | Merge property bags | [make_bag](https://learn.microsoft.com/kusto/query/make-bag-aggregation-function) |
| `make_bag_if` | `make_bag_if(expr, predicate [, maxSize])` | Conditional `make_bag` | [make_bag_if](https://learn.microsoft.com/kusto/query/make-bag-if-aggregation-function) |
| `make_list` | `make_list(expr [, maxSize])` | List of values (order not guaranteed unless `serialize`) | [make_list](https://learn.microsoft.com/kusto/query/make-list-aggregation-function) |
| `make_list_if` | `make_list_if(expr, predicate [, maxSize])` | Conditional list | [make_list_if](https://learn.microsoft.com/kusto/query/make-list-if-aggregation-function) |
| `make_list_with_nulls` | `make_list_with_nulls(expr)` | List **including** nulls | [make_list_with_nulls](https://learn.microsoft.com/kusto/query/make-list-with-nulls-aggregation-function) |
| `make_set` | `make_set(expr [, maxSize])` | Distinct values (dynamic array) | [make_set](https://learn.microsoft.com/kusto/query/make-set-aggregation-function) |
| `make_set_if` | `make_set_if(expr, predicate [, maxSize])` | Conditional distinct set | [make_set_if](https://learn.microsoft.com/kusto/query/make-set-if-aggregation-function) |

`maxSize` caps array length (platform default is limited; do not build unbounded IOC arrays in alert payloads). Sentinel custom details / entities have size caps. [Sentinel service limits](https://learn.microsoft.com/azure/sentinel/sentinel-service-limits)

## Row selectors

| Function | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `arg_max` | `arg_max(ExprToMaximize, * \| ExprToReturn [, …])` | Row that maximizes the expression; `*` returns all columns | [arg_max](https://learn.microsoft.com/kusto/query/arg-max-aggregation-function) |
| `arg_min` | `arg_min(ExprToMinimize, * \| ExprToReturn [, …])` | Row that minimizes the expression | [arg_min](https://learn.microsoft.com/kusto/query/arg-min-aggregation-function) |
| `take_any` | `take_any(expr [, …])` | Arbitrary non-empty value(s) | [take_any](https://learn.microsoft.com/kusto/query/take-any-aggregation-function) |
| `take_anyif` | `take_anyif(expr, predicate)` | Conditional `take_any` | [take_anyif](https://learn.microsoft.com/kusto/query/take-anyif-aggregation-function) |

Custom detection pattern:

```kusto
DeviceEvents
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId) = arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

## Statistical

| Function | Signature | Docs | Citation |
| --- | --- | --- | --- |
| `avg` | `avg(expr)` | Average of non-null values | [avg](https://learn.microsoft.com/kusto/query/avg-aggregation-function) |
| `avgif` | `avgif(expr, predicate)` | Conditional average | [avgif](https://learn.microsoft.com/kusto/query/avgif-aggregation-function) |
| `count` | `count()` / `count(expr)` | Row count (optionally non-null expr) | [count](https://learn.microsoft.com/kusto/query/count-aggregation-function) |
| `countif` | `countif(predicate)` | Count rows matching predicate | [countif](https://learn.microsoft.com/kusto/query/countif-aggregation-function) |
| `count_distinct` | `count_distinct(expr)` | **Exact** distinct count | [count_distinct](https://learn.microsoft.com/kusto/query/count-distinct-aggregation-function) |
| `count_distinctif` | `count_distinctif(expr, predicate)` | Conditional exact distinct | [count_distinctif](https://learn.microsoft.com/kusto/query/count-distinctif-aggregation-function) |
| `dcount` | `dcount(expr [, accuracy])` | **Approximate** distinct count (HLL) | [dcount](https://learn.microsoft.com/kusto/query/dcount-aggregation-function) |
| `dcountif` | `dcountif(expr, predicate [, accuracy])` | Conditional approx distinct | [dcountif](https://learn.microsoft.com/kusto/query/dcountif-aggregation-function) |
| `hll` | `hll(expr [, accuracy])` | Intermediate HLL sketch | [hll](https://learn.microsoft.com/kusto/query/hll-aggregation-function) |
| `hll_if` | `hll_if(expr, predicate [, accuracy])` | Conditional HLL | [hll-if](https://learn.microsoft.com/kusto/query/hll-if-aggregation-function) |
| `hll_merge` | `hll_merge(hllExpr)` | Merge HLL sketches | [hll_merge](https://learn.microsoft.com/kusto/query/hll-merge-aggregation-function) |
| `max` | `max(expr)` | Maximum | [max](https://learn.microsoft.com/kusto/query/max-aggregation-function) |
| `maxif` | `maxif(expr, predicate)` | Conditional max | [maxif](https://learn.microsoft.com/kusto/query/maxif-aggregation-function) |
| `min` | `min(expr)` | Minimum | [min](https://learn.microsoft.com/kusto/query/min-aggregation-function) |
| `minif` | `minif(expr, predicate)` | Conditional min | [minif](https://learn.microsoft.com/kusto/query/minif-aggregation-function) |
| `percentile` | `percentile(expr, percentile)` | Approximate percentile (0–100) | [percentile](https://learn.microsoft.com/kusto/query/percentiles-aggregation-function) |
| `percentiles` | `percentiles(expr, p1 [, p2 …])` | Multiple percentiles as columns | [percentiles](https://learn.microsoft.com/kusto/query/percentiles-aggregation-function) |
| `percentiles_array` | `percentiles_array(expr, dynamic([p…]))` | Percentiles as dynamic array | [percentiles_array](https://learn.microsoft.com/kusto/query/percentiles-array-aggregation-function) |
| `percentilesw` | `percentilesw(expr, weight, p1 [, …])` | Weighted percentiles | [percentilesw](https://learn.microsoft.com/kusto/query/percentilesw-aggregation-function) |
| `percentilesw_array` | `percentilesw_array(expr, weight, dynamic([p…]))` | Weighted percentile array | [percentilesw-array](https://learn.microsoft.com/kusto/query/percentilesw-array-aggregation-function) |
| `stdev` | `stdev(expr)` | Sample standard deviation | [stdev](https://learn.microsoft.com/kusto/query/stdev-aggregation-function) |
| `stdevif` | `stdevif(expr, predicate)` | Conditional sample stdev | [stdevif](https://learn.microsoft.com/kusto/query/stdevif-aggregation-function) |
| `stdevp` | `stdevp(expr)` | Population stdev | [stdevp](https://learn.microsoft.com/kusto/query/stdevp-aggregation-function) |
| `sum` | `sum(expr)` | Sum of non-null | [sum](https://learn.microsoft.com/kusto/query/sum-aggregation-function) |
| `sumif` | `sumif(expr, predicate)` | Conditional sum | [sumif](https://learn.microsoft.com/kusto/query/sumif-aggregation-function) |
| `tdigest` | `tdigest(expr [, accuracy])` | Intermediate t-digest for percentiles | [tdigest](https://learn.microsoft.com/kusto/query/tdigest-aggregation-function) |
| `tdigest_merge` | `tdigest_merge(tdigestExpr)` | Merge t-digests | [tdigest_merge](https://learn.microsoft.com/kusto/query/tdigest-merge-aggregation-function) |
| `variance` | `variance(expr)` | Sample variance | [variance](https://learn.microsoft.com/kusto/query/variance-aggregation-function) |
| `varianceif` | `varianceif(expr, predicate)` | Conditional sample variance | [varianceif](https://learn.microsoft.com/kusto/query/varianceif-aggregation-function) |
| `variancep` | `variancep(expr)` | Population variance | [variancep](https://learn.microsoft.com/kusto/query/variancep-aggregation-function) |
| `variancepif` | `variancepif(expr, predicate)` | Conditional population variance | [variancepif](https://learn.microsoft.com/kusto/query/variancepif-aggregation-function) |

`percentilew()` (singular weighted) is documented alongside `percentilesw`. Scalar companions for sketches: `dcount_hll()`, `percentile_tdigest()`, `merge_tdigest()` — see [`scalar-functions.md`](scalar-functions.md).

## Tabular `count` operator vs `count()` aggregate

`T | count` is a **tabular operator** (shorthand for `summarize count()`). `count()` inside `summarize` is the aggregate. Both are valid in detections; a lone `count` result is a single number and is a poor alert payload unless you also `extend` context.

## Detection guidance

| Goal | Aggregate |
| --- | --- |
| Threshold on volume | `count()`, `countif()`, `dcount()` |
| Keep latest event columns | `arg_max(TimeGenerated, *)` or `arg_max(Timestamp, ReportId, DeviceId)` |
| Collect command lines / IPs | `make_set()` / `make_list()` with a cap |
| Exact unique users | `count_distinct(UserPrincipalName)` (costlier than `dcount`) |
| Baseline / anomaly hunting | `avg`, `stdev`, `percentile` over `bin(TimeGenerated, 1h)` |

Cross-service ADX proxy queries **do not** support several aggregates (`arg_max`, `avg`, `countif`, `percentile`, …). That restriction is **not** the normal Sentinel workspace case. [Azure Monitor–ADX proxy](https://learn.microsoft.com/azure/azure-monitor/logs/azure-monitor-data-explorer-proxy)
