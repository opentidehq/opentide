# SPL inventory (detections / OpenTide)

This directory inventories **Splunk Processing Language (SPL)** as used in Splunk Enterprise Security (ES) detections and OpenTide `configurations.splunk.query` (and legacy `configurations.splunk.search`) blocks.

It is a **docs inventory**, not a grammar. The engine still owns parsing. Catalogs:

- [`catalogs/spl/commands.toml`](../../catalogs/spl/commands.toml) — commands + eval/stats functions
- [`catalogs/spl/fields.toml`](../../catalogs/spl/fields.toml) — default + CIM + raw Windows fields
- [`catalogs/spl/datamodels.toml`](../../catalogs/spl/datamodels.toml) — `tstats from datamodel=`
- [`catalogs/spl/macros.toml`](../../catalogs/spl/macros.toml) — ESCU / ES macros (never expanded)
- [`catalogs/spl/command-options.toml`](../../catalogs/spl/command-options.toml) — `tstats` option schema

Runtime model: [`DESIGN.md`](DESIGN.md).

## Authored text vs implicit `| search`

**Authored SPL is tokenized as written.** OpenTide does **not** rewrite a leading generating command into the source.

Splunk’s runtime default is:

> The `search` command is implied at the beginning of any search. You do not need to specify the `search` command at the beginning of your search criteria.

Citation: [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search) in the Search Reference.

That implied command is a **Splunk runtime default**, not a source rewrite:

- A Tide rule whose query is `index=main sourcetype=WinEventLog EventCode=4688` is stored and highlighted as that string.
- Splunk then runs it as if `| search index=main sourcetype=WinEventLog EventCode=4688`.
- A query that already starts with a generating command (`| tstats …`, `| inputlookup …`, `| makeresults`) is **not** prefixed with `search`.

CI oracle `implicit-search-prefix` (`testdata/oracles/exceptions.toml`) records this: authored text is not rewritten with an implicit `| search`. See also `docs/LANGUAGE.md` (SPL section) and `docs/ARCHITECTURE.md` (injection table).

## Command kinds

Splunk documents six overlapping types ([Command types](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commandsbytype), [Types of commands](https://docs.splunk.com/Documentation/Splunk/latest/Search/Typesofcommands)):

| Splunk type | Catalog `kind` | Meaning |
| --- | --- | --- |
| Generating | `generating` | Starts a pipeline; returns events or a report from indexes, datamodels, lookups, REST, or synthetic rows |
| Transforming (formerly reporting) | `transforming` | Collapses events into a statistical table |
| Distributable / centralized streaming | `streaming` | Operates event-by-event (indexers or search head) |
| Dataset processing | `dataset` | Needs the whole result set before it can run |
| Orchestrating | `orchestrating` | Changes *how* the search is processed, not the logical result set |

Types overlap. `search` is generating when first and streaming later. `lookup` is streaming unless `local=true` (orchestrating). `fillnull` is streaming with a field list and dataset processing without one.

OpenTide’s catalog uses the five-kind model in the middle column. Dual classification is noted per command in [commands.md](commands.md).

## Detection-shaped pipelines

ES / ESCU / OpenTide `splunk.query` blocks typically look like one of:

```spl
index=* sourcetype=WinEventLog EventCode=4688
| eval process_name=lower(process_name)
| stats count by dest, user, process_name
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("cmd.exe","powershell.exe")
    by Processes.dest, Processes.user, Processes.process_name
| `drop_dm_object_name(Processes)`
| where count > 0
```

```spl
| inputlookup my_watchlist.csv
| eval dest=lower(dest)
```

Bare field-value searches are the common case. Generating commands other than implied `search` must be written with a leading pipe (`| tstats`, `| makeresults`).

## Files in this inventory

| File | Contents |
| --- | --- |
| [commands.md](commands.md) | Search commands relevant to detection searches (generating, transforming, streaming, dataset, orchestrating) |
| [eval-functions.md](eval-functions.md) | Evaluation functions used with `eval`, `where`, `fieldformat` |
| [stats-functions.md](stats-functions.md) | Aggregations for `stats` / `eventstats` / `streamstats` / `tstats` / `chart` / `timechart` |
| [search-syntax.md](search-syntax.md) | Field-value pairs, booleans, wildcards, pipes, subsearches, macros, comments |
| [macros.md](macros.md) | Search macros (`` `name` `` / `` `name(args)` ``), ES/ESCU examples |
| [subsearches.md](subsearches.md) | Bracket subsearches, `return` / `format` / join-append patterns |
| [comments.md](comments.md) | `` ```comment``` `` form vs macros; placement limits |
| [common-fields.md](common-fields.md) | Default Splunk fields plus CIM / ES fields used in detections |
| [cim-fields.md](cim-fields.md) | CIM data-model coverage checklist and critical field set |
| [coverage-gap.md](coverage-gap.md) | Inventory vs current `catalogs/spl/commands.toml` (live counts) |
| [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md) | Exact missing names across catalog / grammar / scm / hover / completions |

## Canonical citations

Use `docs.splunk.com` Search Reference (versionless `latest` URLs):

- [Search Reference home](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
- [Command quick reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands)
- [Commands by category](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commandsbycategory)
- [Command types](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commandsbytype)
- [Evaluation functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions)
- [Statistical and charting functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions)
- [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search)
- [CIM fields](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields)

Newer portal mirrors live under `help.splunk.com`; citations in this inventory keep the `docs.splunk.com/Documentation/Splunk/latest/SearchReference/` form requested for OpenTide.

## Counts (this revision)

Measured from the tables in this directory (aliases and dual-kind rows included; trig evals listed in prose are counted) against the **current** catalog:

| Surface | Documented here | In `catalogs/spl/commands.toml` |
| --- | --- | --- |
| Commands | **~115** unique primary table names (+ aliases / adjacent) | **118** `[[commands]]` |
| Eval functions | **107** (93 table rows + 14 trig) | **109** `kind = "eval"` (includes trig + dual-use math) |
| Stats aggregations | **35** primary table names (+ aliases) | **35** `kind = "aggregate"` (includes `c` / `distinct_count` / `p` / `percentile`) |
| Functions total | — | **144** (`eval` + `aggregate`) |

Remaining gaps (including ~32 rare Search Reference commands still absent): [coverage-gap.md](coverage-gap.md), [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md).

Grammar `catalog_command_name` matches the catalog (no command drift). Authored SPL is still never rewritten with implicit `| search`.
