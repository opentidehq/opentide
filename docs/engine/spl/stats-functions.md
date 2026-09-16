# Statistical and charting functions

Functions used with `stats`, `eventstats`, `streamstats`, `chart`, `timechart`, and (a subset) `tstats` / `mstats` / `geostats` / `sistats`.

Citation: [Statistical and charting functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions)

Related:

- [Aggregate functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions)
- [Event order functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventorderfunctions)
- [Multivalue stats functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Multivaluefunctions)
- [Time functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions)
- [stats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)
- [tstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats)

`tstats` supports most aggregates below except `list()`, `mean()`, `estdc_error()`, and the `per_*` rate helpers. See the [tstats function table](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats).

Most functions treat values as numbers and skip non-numeric. These treat values as **strings** even if they look numeric: `count`, `dc`, `earliest`, `estdc`, `estdc_error`, `first`, `latest`, `last`, `list`, `mode`, `values`. Exceptions: `min`/`max` coerce to numbers when possible (`"1"`, `"1.0"`, `"01"` compare equal).

Rename with `AS`: `count AS event_count`, `dc(user) AS unique_users`.

---

## Detection-critical aggregations

These are the functions the inventory was asked to cover first. They dominate ES / ESCU correlation searches.

| Name | Aliases | Kind | Syntax | Docs | Citation |
| --- | --- | --- | --- | --- | --- |
| `count` | `c` | aggregate | `count` or `count(field)` or `count(eval(field="v"))` | Occurrences where the field is non-empty. Bare `count` counts events. | [count](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `sum` | | aggregate | `sum(field)` | Sum of numeric values. | [sum](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `avg` | | aggregate | `avg(field)` | Average of numeric values. | [avg](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `min` | | aggregate | `min(field)` | Minimum (numeric if possible, else lexicographic). ES: `min(_time) AS firstTime`. | [min](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `max` | | aggregate | `max(field)` | Maximum. ES: `max(_time) AS lastTime`. | [max](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `dc` | `distinct_count` | aggregate | `dc(field)` | Count of distinct string values (`"1"` ≠ `"1.0"`). | [distinct_count](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `median` | | aggregate | `median(field)` | Middle-most numeric value. | [median](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `perc` | `p`, `percentile` | aggregate | `perc<N>(field)` e.g. `perc95(bytes)` | Approximate N-th percentile, N in 1..99. | [perc](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `stdev` | | aggregate | `stdev(field)` | Sample standard deviation. | [stdev](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `var` | | aggregate | `var(field)` | Sample variance. | [var](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `list` | | multivalue | `list(field)` | Up to 100 values, input order. **Not on `tstats`.** | [list](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Multivaluefunctions) |
| `values` | | multivalue | `values(field)` | Distinct values, lexicographic order. | [values](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Multivaluefunctions) |
| `earliest` | | time | `earliest(field)` | Chronologically oldest value of `field`. | [earliest](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `latest` | | time | `latest(field)` | Chronologically newest value of `field`. | [latest](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `first` | | event-order | `first(field)` | First **seen** given input order (often most recent into `stats`). | [first](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventorderfunctions) |
| `last` | | event-order | `last(field)` | Last seen given input order (often oldest into `stats`). | [last](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventorderfunctions) |
| `mode` | | aggregate | `mode(field)` | Most frequent value. | [mode](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `range` | | aggregate | `range(field)` | `max - min` for numeric fields. | [range](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `estdc` | | aggregate | `estdc(field)` | Estimated distinct count (cheaper than `dc` at huge cardinality). | [estdc](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `exactperc` | | aggregate | `exactperc<N>(field)` | Exact percentile; expensive at high cardinality. Prefer `perc` in detections. | [exactperc](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `upperperc` | | aggregate | `upperperc<N>(field)` | Approximate upper bound of the percentile when n > 1000; else same as `perc`. | [upperperc](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |

`first`/`last` follow **pipeline order**, not `_time`. For “oldest/newest by time” use `earliest`/`latest` or `min(_time)`/`max(_time)`.

---

## Other aggregate functions

| Name | Syntax | Docs | Citation |
| --- | --- | --- | --- |
| `mean` | `mean(field)` | Arithmetic mean (not on `tstats`). | [mean](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `stdevp` | `stdevp(field)` | Population standard deviation. | [stdevp](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `varp` | `varp(field)` | Population variance. | [varp](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `sumsq` | `sumsq(field)` | Sum of squares. | [sumsq](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |
| `estdc_error` | `estdc_error(field)` | Theoretical error ratio of `estdc`. Not on `tstats`. | [estdc_error](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aggregatefunctions) |

Percentile family spellings: `perc95(x)`, `p95(x)`, `percentile95(x)`, `exactperc95(x)`, `upperperc95(x)`.

---

## Time / rate functions

Used mainly with `timechart` / `stats` on counters — less common in ES correlation searches, common in operational detections.

| Name | Syntax | Docs | Citation |
| --- | --- | --- | --- |
| `earliest_time` | `earliest_time(field)` | UNIX time of earliest occurrence of `field`. | [earliest_time](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `latest_time` | `latest_time(field)` | UNIX time of latest occurrence. | [latest_time](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `rate` | `rate(field)` | `(latest-earliest)/(latest_time-earliest_time)` per second. Numeric earliest/latest required. | [rate](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `rate_avg` | `rate_avg(field)` | Average rates for an accumulating counter metric. | [rate_avg](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `rate_sum` | `rate_sum(field)` | Summed rates for an accumulating counter metric. | [rate_sum](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `per_day` | `per_day(field)` | Values per day (charting). | [per_day](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `per_hour` | `per_hour(field)` | Values per hour. | [per_hour](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `per_minute` | `per_minute(field)` | Values per minute. | [per_minute](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |
| `per_second` | `per_second(field)` | Values per second. | [per_second](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timefunctions) |

---

## Command matrix

| Function group | `stats` | `eventstats` | `streamstats` | `tstats` | `chart`/`timechart` |
| --- | --- | --- | --- | --- | --- |
| count/sum/avg/min/max/dc | yes | yes | yes | yes | yes |
| perc / exactperc / upperperc | yes | yes | yes | yes | yes |
| median / mode / range / stdev / var | yes | yes | yes | yes (not `mean`) | yes |
| list | yes | yes | yes | **no** | yes |
| values | yes | yes | yes | yes | yes |
| first / last | yes | yes | yes | yes | yes |
| earliest / latest / `*_time` / rate | yes | yes | yes | yes (rate yes; `per_*` no) | yes |
| sparkline() | yes | no | no | no | `chart` only (with `stats`) |

`eventstats` attaches the aggregation to **each event** (dataset processing). `streamstats` is a running aggregation (centralized streaming; `window=`, `current=`, `reset_*`). `stats` replaces events with the table.

---

## Detection patterns

```spl
| stats count min(_time) AS firstTime max(_time) AS lastTime
    dc(src) AS src_count values(src) AS src
    by dest, user, process_name
```

```spl
| tstats count min(_time) AS firstTime max(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name=cmd.exe
    by Processes.dest, Processes.user
```

```spl
| eventstats avg(bytes) AS avg_bytes, stdev(bytes) AS stdev_bytes by dest
| where bytes > avg_bytes + 3 * stdev_bytes
```

```spl
| streamstats window=50 current=true count(eval(action="failure")) AS fails by src
| where fails > 10
```

`count(eval(status>=400))` counts events matching an eval boolean — the usual “conditional count” in detections.
