# SPL implementation gaps (catalog / grammar / scm / hover / completions)

Machine-oriented punch list. Inventory prose lives in the other `docs/spl/*.md` files; this file names **exact tokens** still missing or miswired in the opentide SPL stack.

Measured against:

- `catalogs/spl/commands.toml` — **150** commands, **148** functions (**109** eval + **39** aggregate, including aggregate `sum` / `avg` / `min` / `max`)
- `grammars/tree-sitter-opentide-spl/grammar.js` — 23 dedicated command rules + `catalog_command_name`
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

### Dedicated grammar rules (23, plus the stats family)

```
search where eval stats rex table rename fields dedup
sort head tail join lookup makemv mvexpand tstats
fillnull foreach spath tojson inputlookup outputlookup
```

`stats_command` also covers `eventstats streamstats sistats chart timechart sichart sitimechart geostats`.

---

## B. Eval / stats function gaps

### Trig / hyperbolic

**Resolved in catalog:** `acos` `acosh` `asin` `asinh` `atan` `atan2` `atanh` `cos` `cosh` `hypot` `sin` `sinh` `tan` `tanh`.

### Dual-use names

`sum` `avg` `min` `max` have both an eval row and an aggregate row. Hover and signature help pick the aggregate row inside `stats`, `eventstats`, `streamstats`, `tstats`, `chart`, `timechart`, `mstats`, `sistats`, `sichart`, and `sitimechart`. `function()` still returns the first row (eval).

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
| Comments `` ```…``` `` | Three or more backticks each side, may span lines |
| Macros `` `macro` `` / `` `macro(args)` `` | First-class `macro` node + HighlightSpec `macro` |
| Subsearch `[ pipeline ]` | `subsearch` rule (join + argument_list + search_term) |
| Search clauses | One `search_expression` for the base search, `search`, `tstats ... where` and subsearches |
| `IN (...)` in **search** clauses | `in_clause`, comma- or space-separated |
| `TERM(...)` / `CASE(...)` / tstats `by PREFIX(...)` | `term_clause` / `case_clause` / `prefix_clause`, raw contents (`term_text`) up to `)` or whitespace; the `)` is optional, as in Splunk |
| Eval expressions | `.` concatenation, `like`, `!`, `true()`/`false()`, quoted and `{f}` assignment names, `<<FIELD>>` templates |
| Search values | `search_word`: any run of non-breaking characters (`-1h@h`, `2.0.0`, `svc-x`) |
| Field names | `_field_name`: `identifier` plus `- { } @ $` (`a{}.b`, `alert.attack-time`), exposed as `identifier` |
| Case-insensitive keywords | `as`, `by`, `over`, `output`, `outputnew`, `from`, `where`, `desc` |
| Stats family | One `stats_command` for `stats`, `eventstats`, `streamstats`, `sistats`, `chart`, `timechart`, `sichart`, `sitimechart`, `geostats`; tstats shares `aggregate_item` and `by_clause` |
| Other catalog commands | Permissive `argument_list`: options, fields, globs, strings, numbers, calls, commas, comparisons, subsearches |
| `tstats` `from datamodel=...` | `from datamodel=` + dotted identifiers |
| Leading `\|` generating command | Optional leading pipe on `pipeline`; without it the first stage is search terms (`spl_command_without_pipe` for a command word), and a trailing `\|` parses (`spl_empty_stage`) |
| Argumentless commands | Parse where Splunk accepts them (`spl_empty_command`); a syntax error where it rejects them ([search-syntax.md](search-syntax.md#forms-splunk-accepts-that-are-mistakes)) |

---

## D. `highlights.scm` gaps

| Item | Status |
| --- | --- |
| Dedicated command keywords | Present |
| `(catalog_command (catalog_command_name) @keyword)` | Present |
| `(unknown_command name: (identifier) @error)` | Present |
| Explicit extra strings (`"timechart" @keyword`, …) | Redundant subset; not a coverage hole |
| Function names | scm `@function`; engine remaps catalog hits to `function.builtin` |
| Macro / comment distinctions | Dedicated `macro` vs `comment` (` ``` `) |
| `TERM` / `CASE` / search-clause `IN` | Grammar + `@keyword` |
| AST fallback `catalog_command_name` | **Handled** as `keyword` in `collect_highlights` |

---

## E. Completions / hover

| API | Status |
| --- | --- |
| `completions` after `\|` | All 150 catalog commands |
| `completions` for a command in `command-options.toml` | That command's arguments (enum values after `name=`) |
| `completions` inside `stats` / `tstats` / `chart` / `timechart` | Aggregate functions plus arguments; eval-only names are not offered |
| `completions` otherwise, when the command has no argument schema | All catalog functions |
| `hover` on commands | Catalog docs + citation |
| `hover` on functions | Catalog docs, kind, Search Reference signature, citation. Aggregate kind inside stats-family commands |
| `hover` on a catalogued argument | `command-options.toml` docs + citation |
| Field completions (CIM) | `catalogs/spl/fields.toml` + datamodel-prefixed completions (lineage-prefixed for child datasets) and expected values after `Prefix.field=` |
| CIM checks | `spl_unknown_datamodel`, `spl_unknown_datamodel_field` (near misses only) and `spl_dataset_not_declared` ([cim-fields.md](cim-fields.md)) |
| Macro name completions | `catalogs/spl/macros.toml` after `` ` `` / inside `tstats` |
| Signature help | Command arguments from `command-options.toml`; function `signature` strings; macro `signature` strings |

---

## F. Intentionally deferred

- App/add-on commands (`dbxquery`, ESCU custom commands, …)
- Full rare/ML/UI command set in §A until product scope expands
- Exhaustive CIM field dump beyond detection-critical `fields.toml` (see [cim-fields.md](cim-fields.md))

---

## G. Suggested implementation order

1. ~~Catalog: 14 trig evals + alias rows~~ **done**
2. ~~`hover`: function docs~~ **done**
3. ~~Fallback highlighter: `catalog_command_name` → `keyword`~~ **done**
4. Grammar: split macros vs comments; nest `pipeline` inside general subsearches
5. Catalog: §A rare commands + regenerate `catalog_command_name` / parser
6. Field / macro completion from [cim-fields.md](cim-fields.md) / [macros.md](macros.md)
7. Never implement implicit `| search` source rewrite
