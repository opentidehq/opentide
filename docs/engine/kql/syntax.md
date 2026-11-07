# KQL syntax used in hunting and detections

This page covers query **syntax** (not operators). Control commands that start with `.` are **not** query syntax and are unsupported in detections.

Primary citations:

- [KQL overview](https://learn.microsoft.com/kusto/query/)
- [Tabular expression statements](https://learn.microsoft.com/kusto/query/tabular-expression-statements)
- [Let statement](https://learn.microsoft.com/kusto/query/let-statement)
- [String data type](https://learn.microsoft.com/kusto/query/scalar-data-types/string)
- [Timespan data type](https://learn.microsoft.com/kusto/query/scalar-data-types/timespan)
- [Syntax conventions](https://learn.microsoft.com/kusto/query/syntax-conventions)
- [Identifier naming](https://learn.microsoft.com/kusto/query/schema-entities/entity-names)

## Query shape

A detection/hunting query is one or more **query statements** separated by `;`. Typical pattern:

```kusto
let Lookback = 1d;
let Suspicious = dynamic(["mimikatz", "psexec"]);
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where FileName has_any (Suspicious)
| project Timestamp, DeviceId, ReportId, FileName, ProcessCommandLine
```

Three statement kinds ([overview](https://learn.microsoft.com/kusto/query/)):

| Statement | Role in detections |
| --- | --- |
| `let` | Bind scalars, tables, or query-defined functions |
| Tabular expression | The actual detection (table + `|` operators) |
| `set` | Query options (`set truncationmaxsize=…`). Rare in detections; not a data source |

KQL is **case-sensitive** for tables, columns, operators, and functions. Escape identifiers with `['name with spaces']` or `["name"]`.

**Sentinel analytics:** 1–10,000 characters; no `search *` or `union *`. [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview)

**Defender NRT custom detections:** single table; no `join`/`union`/`externaldata`; **no comments**. [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

## Pipe pipeline

```
Source | Operator1 | Operator2 | …
```

`Source` is a table name, `datatable`, `print`, `range`, a `let`-bound tabular expression, or a function returning a table. Each operator consumes a table and emits a table. Operator **order** affects both results and performance. Filter early (`where TimeGenerated > ago(1d)` before expensive `join`/`parse`).

Citation: [Tabular expression statements](https://learn.microsoft.com/kusto/query/tabular-expression-statements)

## Comments

| Form | Example |
| --- | --- |
| Line | `// Finds encoded PowerShell` |
| Block | `/* multi-line */` |

Citation: comments are documented as `//` in [syntax conventions](https://learn.microsoft.com/kusto/query/syntax-conventions) and [advanced hunting query language](https://learn.microsoft.com/defender-xdr/advanced-hunting-query-language).

**Detection notes:**

- Scheduled Sentinel analytics: comments are allowed and count toward the 10,000-character limit.
- Defender **Continuous (NRT)** custom detections: **comments are not allowed**.
- Do not put secrets in comments; queries are stored.

## Let statements

Citation: [Let statement](https://learn.microsoft.com/kusto/query/let-statement)

```kusto
let Name = Expression;
let Name = [view] (Parameters) { FunctionBody };
```

Rules:

- Every `let` must be followed by `;`.
- **No blank lines** between `let` statements or between `let` and the query (documented requirement).
- `let` binds a **calculation**, not a snapshot. Re-evaluation can differ for non-deterministic expressions; use `toscalar()` or `materialize()` when you need a single value.

### Patterns in detections

| Pattern | Example |
| --- | --- |
| Scalar constant | `let threshold = 5;` |
| Timespan lookback | `let dt = 1d;` then `where TimeGenerated > ago(dt)` |
| Dynamic watchlist-like list | `let LOLBins = dynamic(["certutil.exe","bitsadmin.exe"]);` … `has_any (LOLBins)` |
| Tabular subquery | `let Failed = SigninLogs \| where ResultType != 0;` |
| Scalar UDF | `let IsPrivate = (ip:string) { ipv4_is_private(ip) };` |
| Tabular UDF + `invoke` | `let AddFlag = (T:(ProcessCommandLine:string)) { T \| extend Suspicious = ProcessCommandLine has "Invoke-Mimikatz" };` |
| View | `let Range10 = view () { range MyColumn from 1 to 10 step 1 };` (included in `union`/`search` wildcards) |

Named expressions: [Optimize queries that use named expressions](https://learn.microsoft.com/kusto/query/named-expressions)

`materialize()` caches a tabular subquery for the rest of the query:

```kusto
let Base = materialize(SecurityEvent | where TimeGenerated > ago(1d) | where EventID == 4688);
```

Citation: [materialize()](https://learn.microsoft.com/kusto/query/materialize-function)

## String literals

Citation: [string](https://learn.microsoft.com/kusto/query/scalar-data-types/string)

| Form | Behavior |
| --- | --- |
| `'...'` or `"..."` | Escape `\`, `\'`/`\"`, `\n`, `\t`, `\uXXXX` |
| `@'...'` or `@"..."` | **Verbatim**: backslash is literal. Double the quote to escape it (`@'it''s'` / `@"say ""hi"""`) |
| `` ``` ... ``` `` | Multi-line verbatim (triple backtick). No escape processing |
| `h'...'` / `H"..."` / `h@'...'` | **Obfuscated** literal: stored as `*` in telemetry; still evaluates to the real string |
| Adjacent literals | `"Hello" ', ' @"world!"` concatenates at parse time |

Hunting examples:

```kusto
| where ProcessCommandLine matches regex @'(?i)powershell.*-enc'
| where FolderPath startswith @"C:\Windows\Temp\"
| where ProcessCommandLine has h'super_secret_token'   // still avoid secrets in rules
```

Regex in KQL string literals: backslashes must be doubled in non-verbatim strings (`"\\A"` for `\A`). Verbatim `@'\\A'` or `@'\A'` depending on engine; Defender NRT docs require encoded string literals: `"\\A"`. [Custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

## Timespan literals

Citation: [timespan](https://learn.microsoft.com/kusto/query/scalar-data-types/timespan)

| Literal | Meaning |
| --- | --- |
| `2d` | 2 days |
| `1.5h` | 1.5 hours |
| `30m` | 30 minutes |
| `10s` | 10 seconds |
| `100ms` | 100 milliseconds |
| `10microsecond` | 10 microseconds |
| `1tick` | 100 nanoseconds |
| `timespan(15 seconds)` | 15 seconds |
| `timespan(2)` | 2 days |
| `timespan(0.12:34:56.7)` | 12h 34m 56.7s |
| `timespan(null)` | null |

**Not supported:** `1w` (week). Use `7d`.

Common detection filters:

```kusto
| where TimeGenerated > ago(1d)
| where Timestamp between (ago(2h) .. now())
| where ingestion_time() > ago(1h)
```

`ago(timespan)` and `now()` are special datetime functions tied to query start: [datetime](https://learn.microsoft.com/kusto/query/scalar-data-types/datetime)

## `datatable`

Citation: [datatable operator](https://learn.microsoft.com/kusto/query/datatable-operator)

Inline table (no pipeline input). Used in detections for IOC lists, allowlists, or join dimensions when a watchlist is unavailable.

```kusto
let Iocs = datatable(Indicator:string, Type:string) [
    "192.0.2.1", "ip",
    "evil.example", "domain"
];
DeviceNetworkEvents
| where Timestamp > ago(1d)
| join kind=inner Iocs on $left.RemoteIP == $right.Indicator
| project Timestamp, DeviceId, ReportId, RemoteIP
```

Schema is `ColumnName:ColumnType` pairs; value count must be a multiple of column count.

**NRT-no** if combined with `join` (NRT bans joins). `datatable` alone as the only source is not a useful detection.

## `print`

Citation: [print operator](https://learn.microsoft.com/kusto/query/print-operator)

Emits a single row of scalar expressions. Useful in hunting to test functions; **not** a detection against logs.

```kusto
print ipv4_is_private("10.0.0.1"), ago(1d)
```

Detection validity: **Hunting** (no workspace table → no security events).

## `range`

Citation: [range operator](https://learn.microsoft.com/kusto/query/range-operator)

```kusto
range ColumnName from Start to Stop step Step
```

Generates an arithmetic series table. Used with `make-series` padding or time-bin scaffolds. Uncommon as the sole detection source.

## Semicolons and multiple queries

- Statements in one query: `let A = 1; let B = 2; Table | where …`
- Defender hunting editor: **separate queries with a blank line**; cursor selects which query runs. [Advanced hunting query language](https://learn.microsoft.com/defender-xdr/advanced-hunting-query-language)
- That blank-line editor behavior is **not** the same as `let` rules (lets cannot have blank lines between them).

## `set` statements

Query-level options (not management `.set`). Example: `set query_take_max_records=10001;`. Generally omit from detections; the platform already caps result size.

## Unsupported in detections: control commands

These are **management commands**, not KQL queries. They start with `.` and are rejected / unavailable in Sentinel analytics, Defender hunting, and custom detections.

| Command class | Examples | Citation |
| --- | --- | --- |
| Show metadata | `.show tables`, `.show databases`, `.show table T schema` | [Management commands](https://learn.microsoft.com/kusto/management/) |
| DDL | `.create table`, `.alter table`, `.drop table`, `.create function` | same |
| Ingest | `.ingest`, `.set`, `.append`, `.set-or-append`, `.set-or-replace` | same |
| Other | `.execute database script`, `.clear`, `.load` | same |

The leading `.` is intentionally not valid at the start of a query so management commands cannot be smuggled into queries. [KQL overview — Management commands](https://learn.microsoft.com/kusto/query/)
