# Coverage gap: `catalogs/kql` vs Microsoft Learn inventory

Historical inventory (2026-09-15). The punch list is [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md).

This file compares the machine-readable catalogs under [`/workspace/catalogs/kql/`](../../catalogs/kql/) with the Microsoft Learn–backed inventory in [`/workspace/docs/kql/`](./), plus grammar / highlights / LSP surface gaps.

**Snapshot date:** 2026-09-15 (catalogs already expanded; replaces the stale “16 operators / 8 functions” counts).

## Current catalog counts

| Catalog file | Count | Notes |
| --- | --- | --- |
| [`core/operators.toml`](../../catalogs/kql/core/operators.toml) | **53** | Tabular ops + aliases (`filter`, `limit`, `order`, `mvexpand`) |
| [`core/operators-scalar.toml`](../../catalogs/kql/core/operators-scalar.toml) | **54** | Includes `between`, `!between`, `-`, `*` |
| [`core/functions.toml`](../../catalogs/kql/core/functions.toml) | **409** | 364 `scalar` + 45 `aggregate` (includes `series_*` / `geo_*` / `convert_*`) |
| [`core/types.toml`](../../catalogs/kql/core/types.toml) | **10** | Full scalar type set |
| [`core/evaluate-plugins.toml`](../../catalogs/kql/core/evaluate-plugins.toml) | **22** | `evaluate` plugin names + AM-no warnings |
| [`sentinel/tables.toml`](../../catalogs/kql/sentinel/tables.toml) | **99** | Common first-party + selected connectors |
| [`defender/tables.toml`](../../catalogs/kql/defender/tables.toml) | **65** | Advanced hunting schema tables |

**Still no catalog file for:** control/management commands (parsed + diagnosed as unsupported), syntax constructs.

---

## Inventory vs catalog (remaining gaps)

| Area | Catalog now | Inventory / Learn | Remaining gap |
| --- | --- | --- | --- |
| Tabular operators | **53** | **~55** primary (+ aliases) | **~0** for hunting/detections |
| Evaluate plugins | **22** | **22** | **0** names |
| Control commands | **0** (diagnostics only) | **7** families in [`control-commands.md`](control-commands.md) | Catalog optional |
| Scalar operators | **54** | **~54** documented | **~0** |
| Scalar functions | **364** scalar rows | Learn index **~329** + AM helpers | **~0** vs hunting inventory |
| Aggregation functions | **45** | Learn **46** names | **`hll_merge` kind** (present as `scalar`, should be `aggregate`) |
| Scalar types | **10** | **10** | **0** |
| Sentinel tables | **99** | Inventory ~60 named; Learn connectors **600+** | Inventory covered; long-tail `_CL` out of scope |
| Defender tables | **65** | Learn schema **~65–66** | Truncated `KB`/`Profiles` renamed; watch Learn drift |

---

## Tabular operators

Essentially complete vs [`operators.md`](operators.md), including aliases `filter`, `limit`, `order`, `mvexpand`.

Validity flags exist on a subset (`search`, `externaldata`, `consume`, `render`). Still worth encoding `search *` / `union *`, Defender NRT bans, and multi-result `fork`/`facet`.

Not operators (correctly elsewhere): `materialize()` (function); `workspace()`/`app()`/`resource()` (functions); evaluate plugin names.

---

## Scalar operators

### Catalog

Equality, string (`has` / `contains` / `startswith` / `endswith` / `hasprefix` / `hassuffix` + `_cs` / `!` variants), `in` / `in~`, `matches regex`, IPv4 text ops, `and` / `or` / `not()`, arithmetic `+ - * / %`, comparisons, `between` / `!between`.

### Grammar (`grammars/tree-sitter-opentide-kql/grammar.js`) gaps

Parsed today: equality, `has`/`contains`/`startswith`/`endswith` (+ many `_cs` / `!` forms), `in`/`in~`, `between`, `matches regex`, arithmetic.

**Not tokenized in `comparison_expression`:**

- `hasprefix`, `!hasprefix`, `hasprefix_cs`, `!hasprefix_cs`
- `hassuffix`, `!hassuffix`, `hassuffix_cs`, `!hassuffix_cs`
- `has_ipv4`, `has_ipv4_prefix`, `has_any_ipv4`, `has_any_ipv4_prefix`
- `!between`

### Highlights

Canonical: [`highlights/queries/kql/highlights.scm`](../../highlights/queries/kql/highlights.scm) (synced to grammar `queries/`).

Literal `@operator` rules include `startswith_cs` / `endswith_cs` / `hasprefix*` / `hassuffix*` / `has_ipv4*`. Rules for tokens absent from the grammar will not match until `grammar.js` + generated parser are updated.

---

## Scalar + aggregation functions

Core conversion/datetime/string/dynamic/hash/IP/math/conditionals/window helpers and detection aggregations are present.

### Missing from `functions.toml` (111 Learn scalars)

| Family | Count missing | Inventory |
| --- | --- | --- |
| `series_*` | **51** | Named in [`scalar-functions.md`](scalar-functions.md); full list in [`scalar-functions-geo-series.md`](scalar-functions-geo-series.md) |
| `geo_*` | **52** | Mostly prose in scalar-functions; full Learn list in geo-series doc |
| `convert_*` | **8** | Named in scalar-functions.md |

Low frequency in classic detections; required for 100% KQL completion/hover.

### Kind quirk

`hll_merge` cataloged as `kind = "scalar"`; Learn lists it under [aggregation functions](https://learn.microsoft.com/kusto/query/aggregation-functions).

---

## Types

**Complete:** `bool`, `datetime`, `decimal`, `dynamic`, `guid`, `int`, `long`, `real`, `string`, `timespan`.

LSP still does not hover/complete type names.

---

## Tables

### Sentinel

Catalog (**99**) ⊇ inventory first-party list. Remaining Learn surface is connector / `_CL` long-tail.

### Defender

Catalog (**65**). `DEFENDER_TABLES_MAP` in `opentide-kql` still hard-codes ~18 names for required-column heuristics — out of sync with TOML.

---

## Syntax / control / plugins

| Topic | Docs | Catalog | Engine |
| --- | --- | --- | --- |
| `let`, comments, strings, timespans | [`syntax.md`](syntax.md) | none | grammar parses subset |
| Evaluate plugins | [`evaluate-plugins.md`](evaluate-plugins.md) | **none** | `evaluate` op only |
| Control commands | [`control-commands.md`](control-commands.md) | **none** | unsupported diagnostic |

---

## Completions / hover / diagnostics

From [`crates/opentide-kql/src/lib.rs`](../../crates/opentide-kql/src/lib.rs):

| Feature | Uses |
| --- | --- |
| Completions after `\|` | tabular `operators` |
| Completions elsewhere | `functions` + `tables` + `scalar_operators` |
| Hover | operators, scalar_operators, functions, tables |
| Diagnostics | unknown tabular op, render warning, control command, unknown table, fuzzy unknown function |

**Not wired:** types; evaluate plugin names; syntax keyword docs; Defender map from TOML; rich validity beyond a few `warning` strings.

`word_at` only walks `[A-Za-z0-9_-]`, so hover on `matches regex`, `!between`, or `not()` is unreliable.

---

## Recommended backfill order

1. Grammar tokens for `hasprefix*` / `hassuffix*` / `has_ipv4*` / `!between` + regenerate parser.
2. Catalog `functions.toml`: all `series_*`, then `geo_*`, then `convert_*`.
3. New `catalogs/kql/core/evaluate-plugins.toml`; wire completions after `evaluate`.
4. Fix `hll_merge` kind; expand operator validity flags.
5. Drive Defender required-column map from `defender/tables.toml`.
6. Optional: control-command catalog; type name completions.

See [`IMPLEMENTATION-GAPS.md`](IMPLEMENTATION-GAPS.md) for exact missing names.
