# KQL implementation gaps (punch-list)

Exact names still missing from each opentide surface after the 2026-09-15 catalog expansion.

Related: [`coverage-gap.md`](coverage-gap.md), [`evaluate-plugins.md`](evaluate-plugins.md), [`control-commands.md`](control-commands.md), [`scalar-functions-geo-series.md`](scalar-functions-geo-series.md).

Legend: **MUST** = blocks 100% completion/hover/highlight fidelity; **SHOULD** = detection-quality; **NICE** = long-tail.

---

## a) Catalogs (`catalogs/kql`)

### Columns — `sentinel/columns.toml` / `defender/columns.toml`

Detection-critical columns for SecurityEvent, SigninLogs, AuditLogs, Defender endpoint/email/identity tables, plus operator options in `core/operator-options.toml`. Runtime model: [`DESIGN.md`](DESIGN.md).

### `core/operators.toml` — 53 tabular

**Missing primary operators vs inventory:** none.

**Implemented slow-query warnings** (rules: [`DESIGN.md`](DESIGN.md#slow-query-warnings)): `search *` → `kql_unscoped_search`, `union *` → `kql_unscoped_union`, a `*` table → `kql_wildcard_table`, late `where` → `kql_where_not_first`, `join` / `summarize` before a later `project` → `kql_join_summarize_before_project`. They are warnings about cost, not a Sentinel legality check.

**SHOULD — still not emitted:**

- `join`, `union`, `externaldata` — Defender NRT ban
- `fork`, `facet` — multi-result / not for detections
- `find` — unbounded multi-table caveat

### `core/operators-scalar.toml` — 54

**Missing vs inventory/Learn:** none (includes `between`, `!between`, `-`, `*`).

### `core/functions.toml` — **409** (364 scalar + 45 aggregate)

**Missing vs Learn scalar index:** none of the previously listed `convert_*` / `series_*` / `geo_*` families. Remaining Learn drift is long-tail / version-specific names not in the hunting inventory.

**SHOULD — kind fix:** `hll_merge` is cataloged as `scalar`; Learn lists it under aggregations.

### Evaluate plugins — [`core/evaluate-plugins.toml`](../../catalogs/kql/core/evaluate-plugins.toml) — **22**

All 22 names from [`evaluate-plugins.md`](evaluate-plugins.md) are catalogued. Completions after `| evaluate ` and hover are wired. AM-no plugins carry `warning = "am_no"`.