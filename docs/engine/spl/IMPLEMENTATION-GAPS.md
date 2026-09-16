# SPL implementation gaps (catalog / grammar / scm / hover / completions)

Machine-oriented punch list. Inventory prose lives in the other `docs/spl/*.md` files; this file names **exact tokens** still missing or miswired in the OpenTide SPL stack.

Measured against:

- `catalogs/spl/commands.toml` — **150** commands, **144** functions (**109** eval + **35** aggregate)
- `grammars/tree-sitter-opentide-spl/grammar.js` — 17 dedicated command rules + `catalog_command_name`
- `highlights/queries/spl/highlights.scm`
- `crates/opentide-spl/src/lib.rs` — completions / hover / analyze / highlight

Hard rule: **do not** rewrite authored SPL with implicit `| search`. `index=main | head 1` remains `bare_search`.

---

## A. Commands — Search Reference coverage

The previous 32 rare Search Reference names (`abstract` … `x11`) are now in the catalog **and** `catalog_command_name`. Remaining gaps are app commands (`dbxquery`, ESCU custom) and SPL2-only names, which stay out of classic SPL v1.

### Alias-only names (canonical may already be catalogued)

| Alias | Canonical |
| --- | --- |
| `af` | `analyzefields` (also missing) |
| `ctable` | `contingency` (catalogued) |
| `counttable` | `contingency` (catalogued) |
| `discretize` | `bin` (catalogued) |
| `run` | `script` (catalogued) |
| `stash` | `collect` (catalogued) |
| `msearch` | `mpreview` (catalogued) |

### Catalog ↔ grammar drift

**None.** Every catalog command is either a dedicated rule or a `catalog_command_name` literal.

### Dedicated grammar rules (17)

```
search where eval stats rex table rename fields dedup
sort head tail join lookup makemv mvexpand tstats
```

---

## B. Eval / stats function gaps

### Trig / hyperbolic

**Resolved in catalog:** `acos` `acosh` `asin` `asinh` `atan` `atan2` `atanh` `cos` `cosh` `hypot` `sin` `sinh` `tan` `tanh`.

### Dual-use names only stored as `kind = "eval"`

Valid as **stats** aggregations in Splunk; no separate aggregate row (name-unique `function()`):

```
sum
avg
min
max
```

### Stats aliases

**Resolved in catalog:** `c` `distinct_count` `p` `percentile`.

### Deferred (classic detection dialect out of scope)

Newer portal / SPL2-oriented names such as `toarray` `tobool` `tomv` `isarray` `ismv` unless/until classic Search Reference lists them for SPL1.

---

## C. Grammar gaps (syntax)

| Construct | Status |
| --- | --- |
| `bare_search` | Present; must stay non-rewriting |
| `catalog_command` / `unknown_command` | Present |
| Comments `` ```…``` `` | `comment` token is wrong shape (` ``` ` + rest-of-line **or** single-backtick pair) |
| Macros `` `macro` `` / `` `macro(args)` `` | Collides with `comment`; not a first-class node |
| Subsearch `[ pipeline ]` | Only structured inside `join`; elsewhere `[` `]` are punctuation |
| `append` / `appendcols` / `map` / `union` / `multisearch` subsearch bodies | Not parsed as nested `pipeline` |
| `IN (...)` in **search** clauses | Not modeled in `bare_search` / `search_command` (only in eval comparisons) |
| `TERM(...)` / `CASE(...)` | Not modeled |
| `tstats` `from datamodel=...` | Partial (`from` + identifier); not full datamodel path grammar |
| Macro expansion awareness | None (token-level only) |

---

## D. `highlights.scm` gaps

| Item | Status |
| --- | --- |
| Dedicated command keywords | Present |
| `(catalog_command (catalog_command_name) @keyword)` | Present |
| `(unknown_command name: (identifier) @error)` | Present |
| Explicit extra strings (`"timechart" @keyword`, …) | Redundant subset; not a coverage hole |
| Function names | scm `@function`; engine remaps catalog hits to `function.builtin` |
| Macro / comment distinctions | No clean captures (grammar overlap) |
| `TERM` / `CASE` / search-clause `IN` | No captures |
| AST fallback `catalog_command_name` | **Handled** as `keyword` in `collect_highlights` |

---

## E. Completions / hover

| API | Status |
| --- | --- |
| `completions` after `\|` | All 118 catalog commands |
| `completions` otherwise | All catalog functions |
| `hover` on commands | Catalog docs + citation |
| `hover` on functions | Catalog function docs + kind |
| Context-aware eval vs aggregate filtering | Not implemented |
| Field completions (CIM) | **None** |
| Macro name completions | **None** |

---

## F. Intentionally deferred

- App/add-on commands (`dbxquery`, ESCU custom commands, …)
- Full rare/ML/UI command set in §A until product scope expands
- CIM field names as catalog entities (documented in [cim-fields.md](cim-fields.md))

---

## G. Suggested implementation order

1. ~~Catalog: 14 trig evals + alias rows~~ **done**
2. ~~`hover`: function docs~~ **done**
3. ~~Fallback highlighter: `catalog_command_name` → `keyword`~~ **done**
4. Grammar: split macros vs comments; nest `pipeline` inside general subsearches
5. Catalog: §A rare commands + regenerate `catalog_command_name` / parser
6. Field / macro completion from [cim-fields.md](cim-fields.md) / [macros.md](macros.md)
7. Never implement implicit `| search` source rewrite
