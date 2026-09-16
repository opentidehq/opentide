# SPL search commands (detection-relevant)

Inventory of Search Reference commands that appear in (or are adjacent to) Splunk ES / ESCU / OpenTide `splunk.query` pipelines.

Kinds follow OpenTide’s catalog taxonomy (`generating | transforming | streaming | dataset | orchestrating`), mapped from Splunk [Command types](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commandsbytype). Dual types are noted.

Canonical index: [Command quick reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands), [Commands by category](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commandsbycategory).

Citation URLs use `https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/<Name>`.

**Authored SPL is not rewritten.** Implied `| search` is a runtime default — see [README.md](README.md).

---

## Generating

A generating command starts a pipeline. If the first token is not generating, Splunk inserts `search`. Generating commands other than implied `search` are written with a leading `|`.

| Name | Kind | Short docs | Citation | Common flags / clauses |
| --- | --- | --- | --- | --- |
| `search` | generating (first); streaming (later) | Retrieve events from indexes, or filter later using keywords, phrases, wildcards, field-value pairs, booleans, `IN`, CIDR. **Implied at the start of every pipeline that does not begin with another generating command.** | [Search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search) | `index=` `sourcetype=` `source=` `host=` `earliest=` `latest=` `TERM()` `CASE()`; later in pipeline: same terms on remaining fields |
| `tstats` | generating (report; event if `prestats=true`) | Statistical aggregation on **indexed** fields / accelerated datamodels. Faster than `stats` over raw. Dominant ES detection generator. | [Tstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats) | `prestats=` `summariesonly=` `allow_old_summaries=` `fillnull_value=` `append=` `local=` `chunk_size=` `include_reduced_buckets=`; `FROM datamodel=Model.Dataset`; `WHERE` / `IN`; `BY` / `span=` |
| `metadata` | generating | List hosts, sources, or sourcetypes from an index / peer. | [Metadata](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Metadata) | `type=hosts\|sources\|sourcetypes` `index=` `splunk_server=` |
| `inputlookup` | generating (centralized; default `append=false`) | Load a lookup table (CSV / KV Store) as events. Watchlists, baselines, threat intel. | [Inputlookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Inputlookup) | `append=` `start=` `max=` `where` `strict=` |
| `makeresults` | generating | Synthesize empty rows (usually one). Unit-test detections, seed `eval`. | [Makeresults](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Makeresults) | `count=` `annotate=` `splunk_server=` |
| `from` | generating (report or event) | Read a dataset: datamodel, lookup, KV Store, saved search, table dataset. | [From](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/From) | `datamodel:` `lookup:` `savedsearch:` `inputlookup:` |
| `rest` | generating | Call a Splunk REST endpoint and emit entities as events. Admin / audit detections (`/services/authentication/users`). | [Rest](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rest) | `splunk_server=` `count=` `timeout=` `method=` |
| `datamodel` | generating (report) | Inspect or search a datamodel / object. | [Datamodel](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Datamodel) | `search` `flat` `summariesonly=` |
| `inputcsv` | generating | Load a CSV from the search head. | [Inputcsv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Inputcsv) | `append=` `dispatch=` `max=` `start=` `events=` |
| `loadjob` | generating | Replay a finished job’s events or results. | [Loadjob](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Loadjob) | `events=` `artifact_offset=` `ignore_running=` |
| `gentimes` | generating | Generate timestamp rows over a range. | [Gentimes](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Gentimes) | `start=` `end=` `increment=` |
| `metasearch` | generating | Event metadata matching a logical expression. | [Metasearch](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Metasearch) | same modifiers as `search` |
| `mstats` | generating (report; event if `append=true`) | Stats on metric indexes. | [Mstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mstats) | `prestats=` `append=` `span=` `WHERE` `BY` |
| `mpreview` / `msearch` | generating | Sample raw metric data points (`msearch` is an alias). | [Mpreview](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mpreview) | `filter=` `target_per_timeseries=` |
| `pivot` | generating | Pivot against a datamodel dataset. Rare in handwritten ES SPL. | [Pivot](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Pivot) | datamodel / object / cells |
| `savedsearch` | generating | Run a saved search by name. | [Savedsearch](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Savedsearch) | `nosubstitution=` |
| `multisearch` | generating | Run several **streaming** subsearches in parallel. | [Multisearch](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Multisearch) | `[ search ... ]` repeated |
| `set` | generating | `union` / `diff` / `intersect` of two subsearches. | [Set](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Set) | `union` `diff` `intersect` |
| `eventcount` | generating | Count events per index. | [Eventcount](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventcount) | `index=` `list_vix=` `report_size=` |
| `dbinspect` | generating | Index bucket metadata. | [Dbinspect](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Dbinspect) | `index=` `span=` `timeformat=` |
| `walklex` | generating | Terms / indexed fields per bucket. | [Walklex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Walklex) | `index=` `type=` `prefix=` |
| `searchtxn` | generating | Find `transaction`-defined events under constraints. | [Searchtxn](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Searchtxn) | transaction name + search |

---

## Transforming

Transforming (legacy: reporting) commands collapse events into a table. They drop `_raw` unless it was copied into a field.

| Name | Kind | Short docs | Citation | Common flags |
| --- | --- | --- | --- | --- |
| `stats` | transforming | Aggregate statistics, optionally `BY` fields. Core of correlation searches. | [Stats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats) | `allnum=` `delim=`; functions + `BY` / `span=` (see [stats-functions.md](stats-functions.md)) |
| `timechart` | transforming | Time-series chart/table of stats. `_time` is the implicit x-axis. | [Timechart](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timechart) | `span=` `bins=` `limit=` `useother=` `usenull=` `partial=` `cont=` `eval` `BY` |
| `chart` | transforming | Tabular charting stats over one field, split by another. | [Chart](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Chart) | `over` `BY` `span=` `limit=` `useother=` `usenull=` `cont=` |
| `table` | transforming | Keep listed fields, in order, as a table. | [Table](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Table) | field list; wildcards |
| `top` | transforming | Most common values of a field. | [Top](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Top) | `limit=` `countfield=` `percentfield=` `showcount=` `showperc=` `useother=` `BY` |
| `rare` | transforming | Least common values of a field. | [Rare](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rare) | same as `top` |
| `sort` | transforming in catalog; **dataset processing** in Splunk | Sort results by fields. | [Sort](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sort) | `±field` `limit=` `desc` / `asc` |
| `dedup` | streaming (default); dataset if `sortby` / `keepevents=true` | Drop subsequent duplicates of listed fields. Catalog kind: streaming. | [Dedup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Dedup) | `consecutive=` `keepempty=` `keepevents=` `sortby` `N` (keep first N) |
| `transaction` | centralized streaming; dataset in some modes | Group events into transactions (sessionization). | [Transaction](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transaction) | `maxspan=` `maxpause=` `maxevents=` `startswith=` `endswith=` `keepevicted=` `mvlist=` `delim=` |
| `eventstats` | dataset | Compute aggregations and **attach them to each event**. | [Eventstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventstats) | same functions as `stats`; `BY`; `allnum=` |
| `streamstats` | centralized streaming | Running aggregations as events stream. | [Streamstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats) | `window=` `current=` `global=` `time_window=` `reset_on_change=` `reset_before=` `reset_after=` `BY` |
| `xyseries` | streaming if `grouped=false` (default); transforming if `grouped=true` | Pivot to graphable x/y/series format. Inverse of `untable`. | [Xyseries](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Xyseries) | `grouped=` `sep=` `format=` |
| `geostats` | transforming | Stats clustered into geo bins. | [Geostats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Geostats) | `latfield=` `longfield=` `globallimit=` `translatetoxy=` |
| `addtotals` | streaming (row, default); transforming (column totals) | Sum numeric fields per result (or column totals). | [Addtotals](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Addtotals) | `row=` `col=` `labelfield=` `label=` `fieldname=` |
| `contingency` | transforming | Contingency table for two fields. Aliases: `counttable`, `ctable`. | [Contingency](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Contingency) | `maxrows=` `maxcols=` `mincolcoverage=` `usetotal=` |
| `anomalydetection` | transforming / dataset (some modes) | Probability-based anomalous events. | [Anomalydetection](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Anomalydetection) | `method=` `action=` `pthresh=` |
| `mvcombine` | transforming | Collapse events that differ in one field into one mv field. | [Mvcombine](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mvcombine) | `delim=` |
| `sistats` | transforming | Summary-index prep for later `stats`. | [Sistats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sistats) | same as `stats` |
| `sichart` | transforming | Summary-index prep for `chart`. | [Sichart](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sichart) | same as `chart` |
| `sitimechart` | transforming | Summary-index prep for `timechart`. | [Sitimechart](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sitimechart) | same as `timechart` |
| `sitop` | transforming | Summary-index prep for `top`. | [Sitop](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sitop) | same as `top` |
| `sirare` | transforming | Summary-index prep for `rare`. | [Sirare](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sirare) | same as `rare` |
| `timewrap` | transforming | Wrap `timechart` output so each span is a series (WoW). | [Timewrap](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timewrap) | `align=` `series=` `time_format=` |

---

## Streaming

Distributable unless noted. These are the workhorses after `search`/`tstats`.

### Filter, eval, extract

| Name | Kind | Short docs | Citation | Common flags |
| --- | --- | --- | --- | --- |
| `eval` | streaming | Calculate / overwrite fields. See [eval-functions.md](eval-functions.md). | [Eval](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eval) | `field=expr`, comma-separated assignments; `==` inside expressions |
| `where` | streaming | Keep events whose **eval** expression is true. Field-to-field compares live here, not in `search`. | [Where](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Where) | eval expression; `like` `match` `in` `cidrmatch` |
| `rex` | streaming | Extract named groups with PCRE, or `mode=sed` mutate. | [Rex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex) | `field=` (default `_raw`) `max_match=` `offset_field=` `mode=sed` |
| `rex field=<f>` | streaming | Same command; `field=` selects the input (common ES form: `rex field=process "..."`). | [Rex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex) | `field=process` `field=_raw` |
| `regex` | streaming | Keep/drop events matching a regex (filter, not extract). | [Regex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Regex) | `field=` (default `_raw`); `NOT` form |
| `regex field=<f>` | streaming | Same; restrict to a field (`regex field=CommandLine="(?i)powershell"`). | [Regex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Regex) | `field=` |
| `rename` | streaming | Rename fields; wildcards allowed (`AS`). | [Rename](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rename) | `old AS new` `*src AS src*` |
| `fields` | streaming | Keep listed fields (`fields dest, user`) or remove (`fields - _raw, punct`). | [Fields](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fields) | `+` keep (default) `-` remove |
| `fields -` | streaming | Removal form of `fields`. | [Fields](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fields) | `fields - _bkt, _cd, _serial` |
| `head` | centralized streaming | First N results. | [Head](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Head) | `limit=` / `N` `null=` `keeplast=` `eval` condition |
| `tail` | dataset processing | Last N results (needs the full set). Catalog kind in OpenTide: streaming. | [Tail](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tail) | `N` |
| `fillnull` | streaming with field list; dataset without | Replace nulls with a value (default `0`). | [Fillnull](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fillnull) | `value=` field list |
| `filldown` | streaming | Fill null with last non-null. | [Filldown](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Filldown) | field list |
| `convert` | streaming | Convert field values (`ctime`, `mktime`, `dur2sec`, `memk`, `rmcomma`, `none`). | [Convert](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Convert) | `timeformat=` `ctime()` `mktime()` `dur2sec()` `auto()` |
| `replace` | streaming | Replace field **values** (not regex `eval replace()`). | [Replace](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Replace) | `"old" WITH "new" IN field` |
| `setfields` | streaming | Set listed fields to a common value on all results. | [Setfields](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Setfields) | `field=value` |
| `fieldformat` | streaming | Display-time format via eval; does not change stored value or exports. | [Fieldformat](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fieldformat) | `field=eval_expr` |
| `reltime` | streaming | Add human `reltime` from `now` vs `_time`. | [Reltime](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Reltime) | (none) |
| `addinfo` | streaming | Add `info_min_time`, `info_max_time`, `info_search_time`, … | [Addinfo](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Addinfo) | (none) |

### Structured extract / mv

| Name | Kind | Short docs | Citation | Common flags |
| --- | --- | --- | --- | --- |
| `spath` | streaming | Extract JSON/XML paths into fields. | [Spath](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Spath) | `input=` `output=` `path=` |
| `xmlkv` | streaming | Extract XML key-value pairs. | [Xmlkv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Xmlkv) | `maxinputs=` |
| `extract` | streaming | Auto KV extraction from `_raw`. Alias: `kv`. | [Extract](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Extract) | `pairdelim=` `kvdelim=` `auto=` `reload=` `segment=` |
| `kv` | streaming | Alias of `extract`. | [Extract](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Extract) | same |
| `erex` | streaming | Example-based extraction. | [Erex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Erex) | `examples=` `counterexamples=` `fromfield=` |
| `kvform` | streaming | Extract using a form template. | [Kvform](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Kvform) | `form=` `field=` |
| `multikv` | streaming | Extract fields from table-formatted events. | [Multikv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Multikv) | `fields=` `filter=` `forceheader=` `copyattrs=` `multitable=` |
| `makemv` | streaming | Split a single-value field into mv. | [Makemv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Makemv) | `delim=` `tokenizer=` `allowempty=` `setsv=` |
| `mvexpand` | streaming | Explode one mv field into separate events. | [Mvexpand](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Mvexpand) | `limit=` |
| `nomv` | streaming | Collapse mv to a single (first) value. | [Nomv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Nomv) | field |
| `strcat` | streaming | Concatenate strings into a field. | [Strcat](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Strcat) | `allrequired=` src fields dest |
| `bin` | streaming if `span=`; else dataset | Bucket numeric / `_time` into bins. Alias: `bucket`, `discretize`. | [Bin](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Bin) | `span=` `bins=` `minspan=` `aligntime=` `start=` `end=` |
| `bucket` | alias of `bin` | Same as `bin`. | [Bucket](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Bucket) | same as `bin` |
| `rangemap` | streaming | Set `RANGE` (or dest field) from numeric ranges. | [Rangemap](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rangemap) | `default=` `attribute=` `low=0-100` |
| `untable` | streaming | Inverse of `xyseries` / `maketable`. | [Untable](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Untable) | x y value field names |
| `iplocation` | streaming | Geo fields from IP (`City`, `Country`, `lat`, `lon`). | [Iplocation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Iplocation) | `all=` `prefix=` `lang=` |
| `tags` | streaming | Attach knowledge-object tags to fields. | [Tags](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tags) | `outputfield=` `inclname=` `inclvalue=` |
| `xpath` | streaming | Extract via XPath. | [Xpath](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Xpath) | `outfield=` `field=` `default=` |
| `xmlunescape` | streaming | Unescape XML entities. | [Xmlunescape](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Xmlunescape) | `maxinputs=` |
| `tojson` | streaming | Convert events to JSON objects. | [Tojson](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tojson) | `fill_null=` `include_internal=` |
| `fromjson` | streaming | Parse a JSON field into events/fields. | [Fromjson](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fromjson) | `newfield=` |

### Lookups, joins, appends, subsearch helpers

Splunk types vary (join = centralized streaming or dataset; append = transforming/dataset). Catalog uses the kinds below for detections.

| Name | Kind | Short docs | Citation | Common flags |
| --- | --- | --- | --- | --- |
| `lookup` | streaming (`local=false`); orchestrating (`local=true`) | Enrich events from a lookup. | [Lookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Lookup) | `OUTPUT` `OUTPUTNEW` `local=` `update=` |
| `outputlookup` | streaming (write) | Write results to a lookup (CSV / KV Store). Baseline updates. | [Outputlookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Outputlookup) | `append=` `key_field=` `create_empty=` `override_if_empty=` |
| `join` | dataset (no field list); centralized streaming (fields given). Catalog: dataset | SQL-like join to a subsearch. | [Join](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Join) | `type=inner\|left\|outer` `usetime=` `earlier=` `overwrite=` `max=` |
| `append` | dataset / transforming | Append subsearch results as extra rows. | [Append](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Append) | `maxtime=` `maxout=` `timeout=` |
| `appendcols` | dataset | Bind subsearch fields onto rows by position. | [Appendcols](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Appendcols) | `override=` `maxtime=` `maxout=` |
| `appendpipe` | dataset | Append a subpipeline applied to the **current** result set. | [Appendpipe](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Appendpipe) | `[ \| stats ... ]` |
| `selfjoin` | dataset | Join the result set to itself. | [Selfjoin](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Selfjoin) | `overwrite=` `keepsingle=` |
| `return` | streaming (subsearch) | Values to return from a subsearch (`return dest` → `dest=...`). | [Return](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Return) | `$N` `count=` |
| `format` | streaming (subsearch) | Format subsearch rows into `(f=v OR f=v)`. | [Format](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Format) | `mvsep=` `maxresults=` |
| `foreach` | streaming | Templated streaming subsearch per wildcard field. | [Foreach](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Foreach) | `fieldstr=` `matchstr=` `matchsegN=` `[ eval <<FIELD>> = ... ]` |
| `union` | generating / dataset | Merge two or more datasets. | [Union](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Union) | `maxout=` `maxtime=` `timeout=` |
| `map` | dataset | Loop: run a search template per result. Expensive; rare in ES. | [Map](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Map) | `search=` `maxsearches=` |

---

## Dataset processing

Need the whole result set. Some also appear above with dual types.

| Name | Kind | Short docs | Citation | Common flags |
| --- | --- | --- | --- | --- |
| `sort` | dataset | See transforming table. | [Sort](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sort) | `limit=` `±field` |
| `eventstats` | dataset | See transforming table. | [Eventstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventstats) | `BY` |
| `reverse` | dataset | Reverse result order. | [Reverse](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Reverse) | (none) |
| `tail` | dataset | Last N. | [Tail](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tail) | `N` |
| `cluster` | dataset (some modes streaming) | Cluster similar events (`_raw`). | [Cluster](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Cluster) | `t=` `delims=` `showcount=` `labelonly=` |
| `outlier` | dataset | Remove numeric outliers. | [Outlier](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Outlier) | `param=` `usenull=` `usepercent=` `action=` |
| `fieldsummary` | dataset | Per-field summary (count, distinct, types). | [Fieldsummary](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fieldsummary) | `maxvals=` |
| `transpose` | dataset | Rows ↔ columns. | [Transpose](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transpose) | `column_name=` `header_field=` `include_empty=` |
| `uniq` | dataset | Drop exact duplicate events. | [Uniq](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Uniq) | (none) |
| `concurrency` | dataset | Concurrent events from a duration field. | [Concurrency](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Concurrency) | `duration=` `start=` `output=` |

---

## Orchestrating

Do not change the logical result set; they change **where / how** commands run.

| Name | Kind | Short docs | Citation | Common flags |
| --- | --- | --- | --- | --- |
| `localop` | orchestrating | Force subsequent commands to the search head. | [Localop](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Localop) | (none) |
| `noop` | orchestrating | No-op / toggle optimizations. | [Noop](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Noop) | `optimize_searches=` (internal; see docs) |
| `redistribute` | orchestrating | Parallel reduce for high-cardinality `stats`. | [Redistribute](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Redistribute) | `by` fields |
| `require` | orchestrating | Fail the search if prior commands returned zero results. | [Require](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Require) | (none) |
| `lookup` (`local=true`) | orchestrating | Force lookup onto the search head. | [Lookup](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Lookup) | `local=true` |

---

## Aliases (same command, second name)

| Alias | Canonical | Citation |
| --- | --- | --- |
| `bucket` | `bin` | [Bucket](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Bucket) |
| `discretize` | `bin` | [Bin](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Bin) |
| `kv` | `extract` | [Extract](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Extract) |
| `stash` | `collect` | [Collect](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Collect) |
| `run` | `script` | [Script](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Script) |
| `ctable`, `counttable` | `contingency` | [Contingency](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Contingency) |
| `af` | `analyzefields` | [Analyzefields](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Analyzefields) |
| `msearch` | `mpreview` | [Msearch](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Msearch) |

---

## Adjacent commands (rare or unsafe in detections)

Documented in Search Reference but unusual (or dangerous) inside ES correlation searches. Grammar may still see them as `unknown_command` until catalogued.

| Name | Why it shows up / why to avoid | Citation |
| --- | --- | --- |
| `collect` / `stash` | Write to a summary index (not a detector body). | [Collect](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Collect) |
| `delete` | Permanently delete matching events. Never in a detection. | [Delete](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Delete) |
| `sendemail` / `sendalert` | Alert actions, not query logic. | [Sendemail](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Sendemail) |
| `script` / `run` | External script. Not portable in OpenTide rules. | [Script](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Script) |
| `outputcsv` | Write a CSV on the search head. | [Outputcsv](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Outputcsv) |
| `kmeans`, `anomalies`, `anomalousvalue`, `predict`, `trendline`, `x11` | ML / trending; occasional anomaly detections. | [List of commands](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands) |
| `highlight`, `iconify`, `abstract`, `typer`, `findtypes` | UI / event typing. | same |
| `history`, `typeahead` | Interactive / operational. | same |
| `mcollect`, `meventcollect`, `tscollect` | Write metrics / tsidx. | same |
| `geom`, `geomfilter` | Choropleth maps. | same |
| `makecontinuous`, `gauge` | Chart helpers. | same |
| `localize`, `rtorder` | Time localization / real-time ordering. | same |
| `scrub` | Anonymize results. | [Scrub](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Scrub) |

Third-party / app commands (`dbxquery`, `snowincident`, `awssnsalert`, ESCU macros that expand to custom commands) are **not** core Search Reference and are out of scope for the catalog until explicitly added.

---

## ES detection frequency (practical)

Almost every ESCU-style query is a subset of:

1. **Generate:** implied `search` **or** `tstats` (sometimes `inputlookup` / `from` / `makeresults`)
2. **Shape:** `eval` `rex` `rename` `fields` `fillnull` `spath` `lookup` `regex` `where`
3. **Reduce:** `stats` (`count`, `min(_time)`, `max(_time)`, `dc`, `values`)
4. **Optional:** `join` `append` `dedup` `sort` `head` `mvexpand` `bin` `transaction` `eventstats` `streamstats` `table` `outputlookup`

Prioritize catalog/grammar coverage in that order. See [coverage-gap.md](coverage-gap.md).
