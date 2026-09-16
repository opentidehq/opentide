# KQL scalar types

Citation hub: [Scalar data types](https://learn.microsoft.com/kusto/query/scalar-data-types/)

Every expression and column has a scalar type. KQL is **case-sensitive**. Integer literals default to `long`. Use `gettype()` to inspect a value.

| Type | Aliases | Description | Literal examples | Null | Citation | Detections |
| --- | --- | --- | --- | --- | --- | --- |
| `bool` | `boolean` | `true` (`1`) or `false` (`0`) | `true`, `false`, `bool(1)`, `bool(null)` | yes | [bool](https://learn.microsoft.com/kusto/query/scalar-data-types/bool) | Yes |
| `datetime` | `date` | UTC instant (100-ns ticks from 0001-01-01) | `datetime(2015-12-31 23:59:59.9)`, `datetime(2015-12-31)`, `datetime(null)` | yes | [datetime](https://learn.microsoft.com/kusto/query/scalar-data-types/datetime) | Yes |
| `decimal` | — | 128-bit decimal. Arithmetic is slower than `real`; prefer `real` unless high precision is required | `decimal(1.0)`, `decimal(1e5)`, `decimal(null)` | yes | [decimal](https://learn.microsoft.com/kusto/query/scalar-data-types/decimal) | Yes (rare in detections) |
| `dynamic` | — | JSON-like array, property bag, or nested scalar (including KQL types JSON cannot store, e.g. `timespan`) | `dynamic([1,2])`, `dynamic({"a":1})`, `dynamic(null)` | yes | [dynamic](https://learn.microsoft.com/kusto/query/scalar-data-types/dynamic) | Yes |
| `guid` | `uuid`, `uniqueid` | 128-bit GUID `8-4-4-4-12` hex | `guid(74be27de-1e4e-49d9-b579-fe0b331d3642)`, `guid(null)` | yes | [guid](https://learn.microsoft.com/kusto/query/scalar-data-types/guid) | Yes |
| `int` | — | Signed 32-bit integer | `int(32)`, `int(-2)`, `int(null)` | yes | [int](https://learn.microsoft.com/kusto/query/scalar-data-types/int) | Yes |
| `long` | — | Signed 64-bit integer. **Default** for untyped integer and hex literals | `12`, `0xf`, `long(-1)`, `long(null)` | yes | [long](https://learn.microsoft.com/kusto/query/scalar-data-types/long) | Yes |
| `real` | `double` | IEEE-754 64-bit float | `real(1.23)`, `1.23`, `real(null)`, `nan`, `inf` | yes | [real](https://learn.microsoft.com/kusto/query/scalar-data-types/real) | Yes |
| `string` | — | UTF-8 Unicode sequence. **Not null** at ingestion from CSV (missing → empty string). No single-char type | `'abc'`, `"abc"`, `@'C:\path'`, `h'secret'` | no (`isempty` instead of `isnull`) | [string](https://learn.microsoft.com/kusto/query/scalar-data-types/string) | Yes |
| `timespan` | `time` | Time interval (not a clock time) | `1d`, `5m`, `10s`, `100ms`, `timespan(0.12:34:56.7)`, `timespan(null)` | yes | [timespan](https://learn.microsoft.com/kusto/query/scalar-data-types/timespan) | Yes |

## Conversion

Use `to*()` functions (`tobool`, `todatetime`, `todecimal`, `todouble`/`toreal`, `toguid`, `toint`, `tolong`, `tostring`, `totimespan`). Failed conversion returns `null` (empty string stays a string for `tostring`). Prefer typed literals over conversion when the value is constant.

Index: [Conversion functions](https://learn.microsoft.com/kusto/query/scalar-functions#conversion-functions)

## Null behavior (detections)

Citation: [Null values](https://learn.microsoft.com/kusto/query/scalar-data-types/null-values)

- Comparisons with `null` are `false` (`where Col == 0` does not match nulls).
- Use `isnull()` / `isnotnull()` for non-string; `isempty()` / `isnotempty()` for strings.
- Arithmetic with a null operand yields null.
- `and`/`or`: `bool(null) and true` → `false`; `bool(null) or true` → `true`.
- There is no SQL `NOT NULL` column constraint.

## Hunting/detection notes

| Topic | Practice |
| --- | --- |
| Event time | Sentinel: `TimeGenerated` (`datetime`). Defender hunting: `Timestamp` (`datetime`). Custom detections accept either. |
| IDs | Device/user IDs, hashes, GUIDs are usually `string` even when they look like GUIDs. Cast only when needed. |
| JSON payloads | `AdditionalFields`, `RawEventData`, `Properties`, `LocationDetails` are `dynamic` or stringified JSON → `parse_json()` / `todynamic()`. |
| Durations | `ago(1d)`, `1h`, `5m` are `timespan`. Do not confuse with `datetime`. Week suffix `w` is **not** supported. |
| `decimal` | Rare in security tables; Log Analytics columns are typically `int`/`long`/`real`. |

## Related

- [types.toml catalog](../../catalogs/kql/core/types.toml) currently lists 9 types and **omits `decimal`**.
- String literals, timespan suffixes, and `dynamic` access: [`syntax.md`](syntax.md)
- String operators on `string`: [`operators-scalar.md`](operators-scalar.md)
