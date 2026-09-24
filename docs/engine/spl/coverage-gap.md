# Coverage gap: inventory vs `catalogs/spl/commands.toml`

Historical inventory. The punch list is [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md).

Comparison of this docs inventory against the **current** catalog compiled into the engine:

[`catalogs/spl/commands.toml`](../../catalogs/spl/commands.toml)

The catalog is `searchbnf`-informed; OpenTide still owns the grammar. Unknown command tokens become `spl.unknown` / `spl_unknown_command` (`docs/LANGUAGE.md`). Catalog functions drive completions and hover.

**Authored SPL is never rewritten with an implicit `| search`.** That prefix is a Splunk runtime default only (see [README.md](README.md)).

## Headline counts (current)

| Surface | In catalog today | Documented in `docs/spl` | Remaining gap |
| --- | --- | --- | --- |
| Commands (`[[commands]]`) | **150** | Search Reference primary names in [commands.md](commands.md) | Detection-relevant + previously missing 32 rare commands. App/SPL2-only remain out of classic scope. |
| Eval functions (`kind = "eval"`) | **109** | **107** (93 table rows + 14 trig in prose) | Trig now in catalog. Newer portal/SPL2-only names remain out of classic scope. |
| Stats aggregations (`kind = "aggregate"`) | **35** | **35** primary names (+ aliases) | Alias rows `c` / `distinct_count` / `p` / `percentile` added. `sum`/`avg`/`min`/`max` remain **eval** rows only (name-unique lookup). |
| Functions total | **144** | — | — |
| Search syntax | not catalogued (grammar partial) | [search-syntax.md](search-syntax.md), [macros.md](macros.md), [subsearches.md](subsearches.md), [comments.md](comments.md) | Knowledge OK; grammar/LSP modeling incomplete — [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md) |
| CIM / ES fields | not catalogued | [common-fields.md](common-fields.md), [cim-fields.md](cim-fields.md) | Inventory present; no field catalog / completion |

**Catalog ↔ grammar:** 150 commands = 17 dedicated parse rules + 133 `catalog_command_name` literals.

**Completions:** after `|` → all catalog commands; otherwise → all catalog functions.

**Hover:** commands + functions (from catalog docs).

**Highlights:** `highlights.scm` colors dedicated commands + `(catalog_command (catalog_command_name) @keyword)`. AST fallback also treats `catalog_command_name` as `keyword`.

---

## Covered in catalog (118 commands)

```
addinfo addtotals anomalydetection append appendcols appendpipe bin bucket
chart cluster collect concurrency contingency convert datamodel dbinspect
dedup delete erex eval eventcount eventstats extract fieldformat fields
fieldsummary filldown fillnull foreach format from fromjson gentimes geom
geostats head highlight history inputcsv inputlookup iplocation join kmeans
kv kvform loadjob localize localop lookup makecontinuous makemv makeresults
map mcollect metadata metasearch mpreview mstats multikv multisearch
mvcombine mvexpand nomv noop outlier outputcsv outputlookup pivot rangemap
rare redistribute regex reltime rename replace require rest return reverse
rex savedsearch script scrub search searchtxn selfjoin sendemail set
setfields sichart sirare sistats sitimechart sitop sort spath stats strcat
streamstats table tags tail timechart timewrap tojson top transaction
transpose tstats union uniq untable walklex where xmlkv xmlunescape xpath
xyseries
```

## Eval in catalog (109)

Includes detection-common and trig: `if` `case` `coalesce` `cidrmatch` `match` `like` `searchmatch` `in` `true` `false` `null` … JSON `json_*` … math `round` `abs` `ceil`/`ceiling` `floor` … `sum` `random` `min` `max` `avg` bitwise `bit_*`, plus trig/hyperbolic `acos` `acosh` `asin` `asinh` `atan` `atan2` `atanh` `cos` `cosh` `hypot` `sin` `sinh` `tan` `tanh`.

## Aggregates in catalog (35)

```
count dc median perc stdev var list values earliest latest first last mode
range estdc exactperc upperperc mean stdevp varp sumsq estdc_error
earliest_time latest_time rate rate_avg rate_sum per_day per_hour
per_minute per_second c distinct_count p percentile
```

`min` / `max` / `sum` / `avg` are catalogued under **eval** (dual-use names; see gap notes).

---

## Remaining gaps (prioritized)

### 1. Search Reference commands not in catalog (~38)

From [List of search commands](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands) / Command quick reference — uncommon in ES correlation searches:

```
abstract accum addcoltotals analyzefields anomalies anomalousvalue
arules associate autoregress bucketdir cofilter correlate
delta diff findtypes folderize gauge geomfilter iconify
meventcollect msearch outputtext overlap predict rtorder
sendalert trendline tscollect typeahead typelearner typer x11
```

Aliases not present as separate catalog rows (canonical may already exist):

```
af              → analyzefields
ctable, counttable → contingency   (contingency is catalogued)
discretize      → bin              (bin/bucket catalogued)
run             → script           (script catalogued)
stash           → collect          (collect catalogued)
msearch         → mpreview         (mpreview catalogued)
```

App / third-party commands (`dbxquery`, ESCU customs, …) stay out of scope.

### 2. Eval still missing

Trig / hyperbolic (**done in catalog**): `acos` `acosh` `asin` `asinh` `atan` `atan2` `atanh` `cos` `cosh` `hypot` `sin` `sinh` `tan` `tanh`.

**Still deferred:** newer portal / SPL2-oriented names (e.g. `toarray` `tobool` `tomv` `isarray` `ismv`) — not part of the classic detection dialect.

### 3. Stats alias / dual-kind notes

| Name | Status |
| --- | --- |
| `c` `distinct_count` `p` `percentile` | **Added** as aggregate alias rows |
| `sum` `avg` `min` `max` | still only `kind = "eval"` (name-unique `function()` lookup) |

### 4. Syntax / LSP modeling

| Feature | Docs | Engine |
| --- | --- | --- |
| Implied vs authored `search` | [README.md](README.md) | **Must not** rewrite; `bare_search` stays bare |
| Macros `` `name` `` | [macros.md](macros.md) | Grammar `comment` overlaps single-backtick forms |
| Comments `` ```…``` `` | [comments.md](comments.md) | Partial / incorrect delimiters |
| Subsearches `[ ]` | [subsearches.md](subsearches.md) | Full pipeline only inside `join`; otherwise punctuation |
| `IN` / `TERM()` / `CASE()` | [search-syntax.md](search-syntax.md) | `IN`/`LIKE` in comparisons; `TERM`/`CASE` not first-class |
| `AND`/`OR`/`NOT` precedence | [search-syntax.md](search-syntax.md) | Modeled for eval/where, not full search-clause AST |

### 5. Hover / highlight quirks

| Surface | Status |
| --- | --- |
| Command completions after `\|` | OK (118) |
| Function completions | OK (all catalog functions) |
| Command hover | OK |
| Function hover | Wired from catalog docs |
| scm via `catalog_command_name` | OK |
| AST fallback highlighter | Handles `catalog_command_name` as `keyword` |
| Extra explicit scm keyword strings | Redundant with `catalog_command_name` (harmless) |

### 6. Catalog quality nits

Adjacent command rows now have `docs` + `citation`. Re-check if any new adjacent commands are added without them.

### 7. Kind mismatches (policy)

| Command | Catalog `kind` | Splunk notes |
| --- | --- | --- |
| `search` | generating | also streaming mid-pipeline |
| `sort` | transforming | dataset processing in Splunk |
| `tail` | streaming | dataset processing in Splunk |
| `join` | dataset | centralized streaming or dataset |
| `lookup` | streaming | orchestrating if `local=true` |
| `fillnull` | dataset | streaming when field list given |

---

## Suggested next expansion order

1. ~~Add 14 trig eval rows + stats alias rows~~ **done**.
2. ~~Wire function hover~~ **done**.
3. ~~AST fallback `catalog_command_name`~~ **done**.
4. Fix grammar comment vs macro tokens; broaden subsearch parsing.
5. Add ~32 rare commands only if scope expands past detections.
6. Optional CIM field catalog from [cim-fields.md](cim-fields.md).
7. Kind-aware function lookup if `sum`/`avg`/`min`/`max` need aggregate docs distinct from eval.
8. **Never** add an implicit `| search` rewrite.

Exact missing names for implementers: [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md).
