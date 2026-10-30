# Changelog

Notable changes to the opentide language server, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a minor version may change diagnostics and settings.

Each version's first paragraph is its summary: the GitHub Release and [opentide.org/releases](https://opentide.org/releases/language-server/) show it above the change lists. Versions before 0.5.0 were tagged after the fact, each on the commit where that stretch of work ended. The crates still said 0.1.0 then, so a binary built from those tags reports 0.1.0, and none of them was published to crates.io.

## [Unreleased]

### Added

- The KQL engine tracks columns through a query ([#112](https://github.com/opentidehq/language-server/issues/112)): at every operator it knows the columns, their types and the operator that made each one, through `let` values and tabular functions, `union`, `join`, `lookup`, `summarize` (named as Kusto names them: `count_`, `dcount_X`, `arg_max(T, *)`), the `project` family, `extend`, `mv-expand`, `parse` and `distinct`. Hover on a column shows its type and the operator that made or renamed it. `opentide_kql::columns` returns what the pass found, and the slow-query heuristics use it: a `where` on a column an earlier operator makes is no longer `kql_where_not_first`, a pipeline that starts from a `let` is not a table reference, a `let` that ends in `project`, `summarize` or `distinct` counts as narrowed, and `summarize arg_max(T, *)` is not `kql_join_summarize_before_project` (part of [#109](https://github.com/opentidehq/language-server/issues/109) B2 and B3).
- The `sentinel` profile knows every table of the Azure Monitor Logs reference (943, with their columns), the Defender XDR tables the Defender XDR connector streams into a workspace, and the ASIM parsers and ingest-time `ASim*Logs` tables ([#113](https://github.com/opentidehq/language-server/issues/113)). `NTANetAnalytics`, `SentinelHealth`, `AppServiceConsoleLogs` and `DeviceProcessEvents` are no longer unknown. `scripts/sync_azure_monitor_tables.py` and `scripts/sync_asim_schemas.py` generate the catalogs (`catalogs/kql/azure-monitor/`, `catalogs/kql/asim/`) from MicrosoftDocs/azure-monitor-docs and Azure/Azure-Sentinel; attribution is in `NOTICE`.
- KQL hover and completion show a column's description ([#139](https://github.com/opentidehq/language-server/issues/139)): the first sentence of the Azure Monitor Logs reference's, for the 24,213 of 27,237 reference columns that have one. A first sentence no longer ends at `e.g.` or `i.e.`, which also completes four table descriptions (`LAJobLogs`, `PowerBIDatasetsTenant`, ...). Hover describes a column from the table it comes from, so in a `union` or `join` it is that side's table, and on an ASIM column it shows the column's class and schema with the schema's documentation link. `catalogs/kql/azure-monitor/tables.toml` and `catalogs/kql/asim/asim.toml` write each column as a `[[tables.columns]]` / `[[schemas.columns]]` sub-table with named keys instead of positional inline arrays, so a change to one column is a one-line diff. ASIM columns carry no description: Azure-Sentinel has none in machine-readable form. Before a query names a table, column completion still offers only the hand-written columns.
- `kql_unknown_column` (error): a near miss of a documented column of a table or ASIM parser (`_Im_NetworkSession | where DstPortNumbr == 22` suggests `DstPortNumber`), or a name that is not a column after `project`, `summarize`, `distinct` or `count`, or one `project-away`/`project-rename` removed ([#113](https://github.com/opentidehq/language-server/issues/113)). An unknown source, `evaluate` or an operator whose output is not modelled makes the columns open, and nothing below it is reported. Over the 5,130 analytics rules and hunting queries of Azure/Azure-Sentinel it reports nothing.
- `kql_type_mismatch` (error): an operator Kusto does not define for a column's documented type, such as `EventID has "46"`, `TimeGenerated > "2024-01-01"` or `Account between ("a" .. "b")`. Equality is not checked: Kusto accepts `EventID == "4688"`.
- Named arguments parse in a KQL function call (`_Im_NetworkSession(starttime=ago(1d), dstportnumber=22)`, part of [#109](https://github.com/opentidehq/language-server/issues/109) A3), and ASIM parser parameters get signature help.
- Declared datasets ([#114](https://github.com/opentidehq/language-server/issues/114), [opentide#695](https://github.com/opentidehq/opentide/issues/695)): the engine reads the tables, indexes, sourcetypes, macros, index patterns and data views each `visibility.toml` log source names (`opentide_analysis::Catalog.visibility`, `install_visibility`). The language server reads `.opentide/configurations/visibility.toml` at start-up and again on every change, in the editor before it is saved or on disk (it registers a file watcher), and re-checks every open document; text that is not TOML yet keeps the declarations in use. A declared table is known. Once a workspace declares tables for a platform, a table it does not declare is `kql_table_not_declared` (warning), with a code action that adds it to the platform's log source in `visibility.toml`, or appends one; a workspace that declares nothing sees no change. `opentide_core::datasets` answers per platform and kind, and `*` in a declared name matches any run of characters.
- SPL: the CIM catalog holds every data model, dataset and field, generated from splunk/pytest-splunk-addon by `scripts/sync_cim_datamodels.py` ([#115](https://github.com/opentidehq/language-server/issues/115)). After `tstats ... from datamodel=`, `| datamodel`, `| from datamodel:` or `| pivot`, a near miss of a CIM field is `spl_unknown_datamodel_field` (`Processes.proces_name` suggests `Processes.process_name`) and a near miss of a data model or dataset is `spl_unknown_datamodel`; both are errors. Fields a site adds to its models, and fields after `drop_dm_object_name`, are not checked. Completion offers lineage-prefixed fields and CIM's expected values. In a workspace whose `visibility.toml` declares Splunk `indexes`, `sourcetypes` or `macros`, an undeclared `index=`, `sourcetype=` or base-search macro is `spl_dataset_not_declared` (warning), with the code action that declares it. Over the 2,611 searches of splunk/security_content none of the new errors fires.
- Elastic: where every index a query reads holds ECS documents (`logs-*` data streams, or indices a log source marks `ecs = true`), ES|QL, EQL, Kibana KQL and Lucene fields are checked against ECS ([#116](https://github.com/opentidehq/language-server/issues/116)). `ecs_type_mismatch` is an error for what Elasticsearch rejects (`FROM logs-* | WHERE source.ip LIKE "10.*"`, a wildcard on an `ip` field, `:` on a number in EQL); `ecs_unknown_field` warns about a near miss under an ECS field set (`process.nmae` suggests `process.name`). In a workspace that declares Elastic datasets, a rule's `index`, `threat.index`, `data_view_id` and an ES|QL `FROM` that no declared index pattern or data view covers are `elastic_dataset_not_declared` (warning), in the editor and in `analyze_queries` alike, with the code action that declares them. Over the 1,269 ECS queries of elastic/detection-rules none of them fires.
- The diagnostic codes for the dataset tiers are in `opentide_core::codes`: `kql_table_not_declared`, `kql_unknown_column`, `kql_type_mismatch`, `spl_unknown_datamodel`, `spl_unknown_datamodel_field`, `spl_dataset_not_declared`, `ecs_type_mismatch`, `ecs_unknown_field`, `elastic_dataset_not_declared`.
- `InjectedQuery::platform` and `QueryReport::platform`: the platform a query runs on, as a `configurations` key: the block's key for a rule query, the entry's `system` for a hunt, whose path does not name it. It picks the KQL profile and Lucene dialect for hover, completion and diagnostics, so a `defender_for_endpoint` hunt is checked against Defender's tables. `opentide_tide::hunt_query_language` maps a hunt's `system` (and Elastic `language`) to its language.
- `kql_deprecated_operator` (warning): `containscs`, `notcontains` and `notcontainscs`, legacy spellings Kusto still parses, suggest `contains_cs`, `!contains` and `!contains_cs` ([#125](https://github.com/opentidehq/language-server/issues/125)).
- SPL: `spl_parse_error` now means Splunk's own parser rejects the query; a form Splunk accepts but that does nothing, returns nothing or searches for literal words has a code of its own ([#135](https://github.com/opentidehq/language-server/issues/135)), each checked against Splunk 10.6.1:
  - `spl_empty_command`: a command with no arguments. `where`, `search`, `fields`, `eventstats`, `streamstats`, `sistats` and `lookup` do nothing (warning); `stats` returns no results and `| inputlookup` with no table fails at run time (error). `head`, `spath`, `fillnull` and `tojson` have defaults and are not reported.
  - `spl_empty_stage` (warning): a trailing `|` (`... | stats count |`), which Splunk ignores.
  - `spl_command_without_pipe` (error): the query starts with a command name and no `|` (`tstats count where index=a by sourcetype`), so Splunk searches for the words and returns nothing. The fix adds the `| `. A command word followed by one term or none (`tstats`, `delete user`) is not reported, nor is `search ...`.
- The Splunk Machine Learning Toolkit commands `fit`, `apply`, `score`, `summary`, `listmodels` and `deletemodel` are in the SPL catalog, marked `app = "MLTK"`, with hover and completion ([#123](https://github.com/opentidehq/language-server/issues/123)).
- `spl_search_operator` (error): `==`, `<>`, `=>`, `=<` or `!~` in an SPL search clause ([#136](https://github.com/opentidehq/language-server/issues/136)). Splunk accepts them, but the comparison never matches, so a detection that uses one never fires (`| search status==200` matches nothing); in `tstats … where` the search fails at run time, and in `inputlookup … where` the comparison is ignored. The quick fix rewrites `==`, `<>`, `=>` and `=<` to `=`, `!=`, `>=` and `<=`. `=~` is a warning: it compares with a value that starts with `~`, not a regular expression. Search clauses are the base search, `| search`, a subsearch's search, `tstats … where` and `inputlookup … where`; `eval`, `where`, quoted values, comments and macro arguments are never read.

### Changed

- `kql_join_summarize_before_project` no longer fires for `summarize` ([#109](https://github.com/opentidehq/language-server/issues/109) B3): `summarize` already returns only the columns it names, and projecting before `arg_max(T, *)` would change its result. A `join` is warned only when its input is still wide: a `summarize`, `distinct` or `count` earlier in the pipeline narrows it, as does a `union` of `let`s that each end in `project`, `summarize` or `distinct`. A wide table straight into `join` with a later `project` still warns. The code keeps its name.
- `kql_where_not_first` no longer fires for a `where` on a column the pipeline's source does not have, such as one a `join` brought in from its right side ([#109](https://github.com/opentidehq/language-server/issues/109) B2).
- Under the `sentinel` profile, a table the engine does not know is a `kql_unknown_table` warning, not an error ([#111](https://github.com/opentidehq/language-server/issues/111), part of [#110](https://github.com/opentidehq/language-server/issues/110)). The engine cannot see a workspace's tables, so a custom `_CL` table or a connector's table failed every `opentide validate` run since opentide 0.19.0. The message says `'X' is not a table opentide knows; if the workspace holds it, declare it in visibility.toml`, and a misspelt known table (`SigninLog`) still gets its suggestion. The `defender_for_endpoint` profile still reports an error. `opentide_kql::Catalog` has a `profile` field, and its `TableRow` a `documented` one.
- A `union` leg is checked like a pipeline's source, except under `union isfuzzy=true`.
- The SPL grammar accepts what Splunk's parser accepts ([#135](https://github.com/opentidehq/language-server/issues/135)): `where`, `search`, `fields`, `eventstats`, `streamstats`, `sistats`, `stats` and `lookup` with no arguments, `| inputlookup` with no table as the first command, and a trailing `|`. A query that does not start with `|` is search terms, as Splunk runs it (`search <text>`), so a leading `bogus x` or `tstats count ...` is no longer `spl_unknown_command` or `spl_parse_error`; after a `|` and at the start of a subsearch a word is still a command. An empty stage before another (`| | stats`), an empty last stage in a subsearch, `| inputlookup` with no table later in a pipeline, and `| index=a` stay syntax errors, as in Splunk.
- SPL searches accept `==`, `<>`, `=>`, `=<` and `!~`, with or without a term on either side (`x==1`, `x == 1`, `a==`), as Splunk's parser does in a base search, `search`, a subsearch and `inputlookup ... where` ([#136](https://github.com/opentidehq/language-server/issues/136)). Splunk splits them into separate terms, so they never match; that is a lint, not a syntax error. `tstats ... where` still rejects them, as Splunk does ("WHERE clause is not an exact query"). A `|` inside `TERM(` or an open `(` ends the stage, as in Splunk (`TERM(x|y)` runs the command `y)`), except inside quotes, comments, macros and a subsearch's `[ ]`.
- An SPL syntax error caused by unbalanced parentheses says so, on the parenthesis: `unbalanced parentheses: this ')' has no matching '('` or `this '(' is never closed`.
- `spl_unknown_command` is a warning, not an error: an app on the search head can add commands the engine cannot know (DECRYPT2's `decrypt`, MISP42's `mispsearch`), and `opentide validate` failed on searches that run ([#123](https://github.com/opentidehq/language-server/issues/123)). The message says so: `'X' is not a command opentide knows; if an app on the search head provides it, declare it`. A name one edit from a known command (`statz`, or `stast` with two letters swapped) is still an error, and the suggestion stays: `stast` now suggests `stats` rather than `stash`, since a swap of two adjacent letters counts as less than one edit.

### Fixed

- Queries are extracted from a Tide object's YAML structure, not from lines that say `query:` or `search:` ([#118](https://github.com/opentidehq/language-server/issues/118)). A Splunk notable's drilldown search (`configurations.splunk.actions.notable.drilldown.search`, a `$token$` template) is no longer analysed as the rule's query `configurations.splunk.search`; a `query:` or `search:` nested anywhere else under a platform block is not a query either. Each response hunt (`response.procedure.searches[]`) is analysed in the language its `system` names whatever the order of its keys, and reported at its own path (`response.procedure.searches.0.query`), not as the rule's `configurations.<system>.query`; a `system` that is not a platform identifier (`Sentinel`, `Splunk ES`) is free text and is not analysed. A folded (`>`, `>-`) or indentation-indicated (`|2`) block scalar is analysed as its value rather than as the text `>-`, and a plain scalar on the line below its key or over several lines as the YAML value. Diagnostics map back through the folding to their line and column in the file.
- A quoted query (`query: "SecurityEvent\n| take 1\n"`, as `yaml.safe_dump` writes one, or a single-quoted query over several lines) is analysed as its value, escapes decoded and lines folded, not as its source text ([#105](https://github.com/opentidehq/language-server/issues/105)).
- KQL typed scalar literals parse as literals, not calls: `datetime(2024-01-01 10:00:00)`, `timespan(1d)`, `time(0s)`, `long(null)`, `double(0)`, `guid(00000000-...)` and the other `bool`, `int`, `real`, `decimal` forms were `kql_unknown_function`, and a date with a space or a `T` was also a `kql_parse_error` ([#125](https://github.com/opentidehq/language-server/issues/125), [#109](https://github.com/opentidehq/language-server/issues/109)). As in Kusto, the value runs to `)` on the same line, right after the type name.
- KQL forms Kusto accepts parse ([#109](https://github.com/opentidehq/language-server/issues/109) A3), each followed by the column pass:
  - a doubled quote in a verbatim string is one quote: `@"{""a"":""b""}"`, `replace_regex(x, @"\[|\]|""", "")`, `@'it''s'`;
  - `.[...]` access on a dynamic value: `d.["a.b"]`, `d.[0].n`;
  - quoted identifiers, wherever a column is read or named: `where ['c'] > 0`, `project ["Display Name"] = tostring(n)`, `project-rename`, `project-away`, `project-keep`, `project-reorder`. The name is the column it quotes;
  - `parse-where`, which makes the same columns as `parse`: `parse-where P with * "a" T`;
  - `distinct` with named expressions and `*`: `distinct b = tolower(a)`, `distinct *`. A named expression is an output column, so a column it only reads is `kql_unknown_column` after it.

  A named argument to a built-in function, `summarize by tostring(Key=Name)`, already parses: Kusto's grammar takes `name = value` as any call's argument, and whether the function has that parameter is not syntax.
- `externaldata (c:string) [@"https://..."] with (format="csv")` parses wherever a tabular expression may start: a `let` value, a pipeline source, and inside `in ((...))` ([#125](https://github.com/opentidehq/language-server/issues/125)). Without its URI list it is still a syntax error.
- Inside a function body a tabular parameter, `(T:(x:string))` or `(T:(*))`, is a table: `T | where ...` was `kql_unknown_table 'T'` ([#125](https://github.com/opentidehq/language-server/issues/125)).
- `union` takes calls as legs (`union isfuzzy=true g("a"), g("b")`), and `containscs` parses ([#125](https://github.com/opentidehq/language-server/issues/125)).
- The KQL operators with their own syntax parse: `range x from 1 to 3 step 1` (also as a source), `project-reorder x asc`, `top-nested 3 of x by count()`, `fork (take 1) (take 2)`, `facet by x`, `sample-distinct 1 of x`, `scan ... with (step s: x == 1;)` and `partition by x (take 1)` were `kql_parse_error` ([#125](https://github.com/opentidehq/language-server/issues/125)).
- SPL search clauses from deployed detections no longer report `spl_parse_error` ([#120](https://github.com/opentidehq/language-server/issues/120)). One `search_expression` serves the base search, `search`, `tstats ... where` and subsearches: `TERM()` and `CASE()` take their contents raw (`TERM(EventID=4688)`, `TERM(user=)`), as Splunk does even when the `)` is missing (`TERM(x` before whitespace, a pipe or the end), and tstats groups by `PREFIX(src=)`, which is still an error as a `where` term; a field may be quoted (`"a.b"=x`) or hold `-` and `{}`; a value may be any run of non-breaking characters (`earliest=-1h@h`, `latest=now()`, `version=2.0.0`, `host=S-RC*`, `rank=-1`); `IN` takes a space-separated list; a search may start with a quoted phrase or `NOT`; and `tstats ... by _time span=1h` parses. Upper-case `AND`, `OR` and `NOT` are reserved, so `a AND OR b`, a leading `OR` and a trailing `NOT` are still syntax errors; a command that takes a search in its arguments (`metasearch index=a OR index=b`) still gets them.
- An SPL comment may span lines and open with more than three backticks (```` ```` note ``` ````). A second line used to become `unknown SPL command`.
- SPL `eval` and `where` expressions from deployed detections no longer report `spl_parse_error` ([#121](https://github.com/opentidehq/language-server/issues/121)): `.` concatenates (`a."-".b`; a name no longer ends in a dot), `true()` and `false()` are functions, `like` is an operator in lower case too, `!` negates, an assignment may name a quoted (`"a.b"=`) or dynamic (`{f}=`) field, `foreach` templates (`<<FIELD>>`, `r<<MATCHSTR>>`) are names, and a subsearch or a `$token$` may stand for a value. `*` stays multiplication.
- SPL command arguments from deployed detections no longer report `spl_parse_error` ([#122](https://github.com/opentidehq/language-server/issues/122)). Keywords are case-insensitive (`rename a as b`, `lookup t ip AS src OUTPUT x`, `stats ... BY`); a field name may hold `-`, `{}`, `@` and `$` (`a{}.b`, `alert.attack-time`, `t-include.csv`); field lists and aggregates take globs (`values(*) as *`, `rename DNS.* as *`) and doubled or trailing commas. `stats`, `eventstats`, `streamstats`, `sistats`, `chart`, `timechart`, `sichart`, `sitimechart` and `geostats` share one rule (options, aggregates with `as`, `over`, `by ... span=`), which `tstats` reuses for its aggregates and `by` clause, with options after the aggregates and `by PREFIX(x=)`. `rename`, `lookup` (`OUTPUT`/`OUTPUTNEW`, with or without fields), `sort` (`sort 0 a`, `-a limit=0`, `num(x) desc`), `rex`, `fillnull`, `foreach`, `spath`, `tojson`, `join`, `mvexpand`, `inputlookup` (options before or after the table, `where`) and `outputlookup` have rules of their own; every other catalog command takes a permissive argument list (options, fields, globs, strings, calls, commas, comparisons, subsearches), so a known command is never a syntax error because its arguments are not modelled. chart and timechart take a trailing `where count > 10` or `where max in top5`; `geostats` takes options alone; a macro may stand for a field, table or aggregate, and a quoted name for a by-field. `rename a as`, `stats values(` and `lookup t` with no field are still syntax errors.
- SPL commands Splunk's parser rejects with no arguments are syntax errors again ([#135](https://github.com/opentidehq/language-server/issues/135)): `append`, `top`, `rare`, `transaction`, `bin` and `geostats` were accepted, as were 42 other catalogued commands with no rule of their own (`xyseries`, `regex`, `iplocation`, `rest`, `metadata`, ...). `geostats` with a `by` clause and no aggregate is an error too.
- An SPL syntax error points at the token the parser could not place, not the whole query: `spl_parse_error` is reported on the first bad token of each error region (`SPL syntax error: unexpected '.'`), on the `(` or `[` that is never closed, or where a token is missing, at most five per query ([#119](https://github.com/opentidehq/language-server/issues/119)). Every SPL error ran from the first line to the end of the query.
- `spl_unknown_command` is reported only for a name in command position (after a `|`, first in the query or a subsearch) outside an error region. A word that error recovery stranded, such as `dest` in `| lookup t-x.csv key AS dest OUTPUT c AS m`, was reported as an unknown command ([#119](https://github.com/opentidehq/language-server/issues/119)).
- `spl_wildcard` and `spl_leading_not` describe the cost of reading the index, so they now look only at a base search, the first stage of the query or of a subsearch ([#124](https://github.com/opentidehq/language-server/issues/124)). A later `| search NOT outcome="Failure"` or `| search value="*@*"` filters rows already in the pipeline and is no longer flagged. `field=*` and `field="*"` are the existence check and are never `spl_wildcard`; a bare `*` term still is. A leading or mid-token wildcard is flagged only when nothing else narrows the read: an `index=`, `sourcetype=`, `source=` or `host=` value, `TERM()`, `PREFIX()` or a macro (`index=a src_user!="*$"` is fine, `index=* *foo*` is not).

## [0.6.0] - 2026-10-29

The host release: opentide compiles the engine into its Python package and drives it through a new host API, each Tide object is checked against the schema revision it names with catalogs from opentide 0.18.0's own generator, and `@opentide/lsp-client` works on stdio, a browser worker, and WASI.

### Added

- `opentide_analysis::set_default_catalog` replaces the bundled Tide catalogs for the whole process whenever no workspace catalog is installed, so a host that generates them from its own models (opentide) is never behind the snapshot compiled in, including after `initialize` finds no workspace catalog, and `opentide_lsp::use_host_catalogs()` keeps `initialize` from replacing them with a committed workspace copy ([opentide#677](https://github.com/opentidehq/opentide/issues/677)).
- `opentide_analysis::bundled_catalog()` returns the Tide catalogs compiled into the engine, as their files hold them, so a host can tell whether the engine it bundles matches its own models ([#99](https://github.com/opentidehq/language-server/issues/99)). opentide's CI fails when it does not.
- Each Tide object is checked against the schema revision its `metadata.schema` names ([#98](https://github.com/opentidehq/language-server/issues/98)). The field catalog has rows per revision (`rule::1.0`, `rule::1.1`); required fields come from it rather than three checks hard-coded for `rule::1.0`, so a `rule::1.1` without `description` is reported; and a key the object's revision does not define is a `schema_validation` error where it is (`field 'metadata.reviewed' is not defined in rule::1.0`), except the legacy spellings opentide accepts (a splunk block's `search`). Catalogs keyed by family, from an older `opentide generate schemas`, still load. Every field with an enum in the catalog is checked (`vocab_unknown`), not only a hand-picked few: `response.alert_severity`, `objective.type`, `objective.composition.strategy` and the signals' fields were not.
- `recommended_field_missing` (warning): a field the templates ask for and opentide validate does not require (a rule's `configurations` and `response`) is missing. The catalog's `required` follows what validation requires, and such fields are `recommended`.
- `opentide-analysis` re-exports every type its functions take and return, so a host (the `opentide` Python package, an editor) depends on it alone. Its crates.io page shows a usage example, run as a doctest.
- `cargo binstall opentide-lsp` downloads the release binary for the target instead of compiling the workspace.
- A host API on `opentide-analysis` for the `opentide` Python package ([opentide#332](https://github.com/opentidehq/opentide/issues/332), [#16](https://github.com/opentidehq/language-server/issues/16)): `analyze_queries` reports every query a Tide object carries, with its language, YAML path, place and diagnostics, including queries with no finding; `analyze_query` checks one query with its platform's profile (Defender KQL, Carbon Black Lucene, an ES|QL stack); `install_catalog` replaces the bundled Tide field and deprecation catalogs with a workspace's; `analyze_with_index` reuses one workspace index across files; `VERSION`.
- `opentide_core::codes::ALL` lists every diagnostic code, and `codes::describe` gives each one a sentence, for hosts that explain a code (`opentide explain`).
- `opentide-lsp` is also a library (`opentide_lsp::run_stdio`), so a host can serve the protocol from its own process.
- The server and `opentide-lsp analyze` read the workspace field catalog `.opentide/lsp/catalogs/generated/fields.json`, which `opentide generate schemas` writes, as well as `deprecations.json`. Hover, completion and vocabulary checks then follow the workspace's schemas, custom vocabulary included. A catalog that does not parse is reported on stderr, and the bundled one is used.

### Fixed

- `pydantic_object_issues.py` validates each object with its revision's model, not the family's first one.
- A rule's `severity: High` was reported as `vocab_unknown` when the workspace had no generated catalog: the bundled Tide catalogs came from opentide 0.16.1, which checked a rule's severity against the threat severity scale. They are generated from opentide 0.18.0 now, where it takes `alert_severity` values, and hover shows the field descriptions 0.18.0 added.
- A diagnostic inside a block-scalar query (`query: |`) after a non-ASCII character (`é`, `🔥`, an accented comment) pointed too far right, and could spill onto the next line: the injection map counted characters where it is indexed by bytes. Semantic tokens and hover inside the query moved the same way.
- An injected query's span starts at its text, not at the indentation of its first line.
- The shape check reads YAML as opentide does: a `<<` merge key fills the fields it merges instead of being an unknown key; a key that is not a string (`1: x`) is not a field; a value outside its enum in the second item of a list is reported on that item, and each bad item once; an unknown key that is quoted, non-ASCII or in a flow mapping is placed on its key, or on the nearest key above it, never at the top of the file.
- A quoted query key (`"query": |`, `'sentinel':`) is still a query: it was left unchecked.
- A KQL query may start with `search` or `find` (`search "mimikatz"`, `search in (SecurityEvent) "x"`, `find in (T) where ...`): it was a `kql_parse_error`, and only `T | search ...` parsed.
- A block-scalar query with an indentation indicator (`query: |2`) whose later line is indented less than the first and holds a multi-byte character no longer panics.
- `scripts/sync_opentide_schemas.py --check` reports a reference schema opentide no longer registers, which writing removes.
- `rootUri` and document URIs are percent-decoded, and a Windows drive (`file:///c%3A/...`) becomes `c:/...`, so a workspace whose path has a space or a drive letter finds its objects and catalogs. Locations the server returns are percent-encoded.
- `opentide-lsp analyze` on a `.kql`, `.spl`, `.esql`, `.eql`, `.kuery` or `.lucene` file no longer reads the directories around it. Outside a workspace it walked the file's grandparent directory, so one YAML file there that was not UTF-8 failed the command.
- One unreadable workspace file (not UTF-8, no permission) no longer drops the whole object index. The stdio server reported every reference to another object as `invalid_ref`, and `analyze` on a Tide object failed. Now that file is left out, and the rest of the workspace still resolves.

### Changed

- The other library crates say on crates.io that they are engine components and point to `opentide-analysis`.
- The workspace deprecation overlay is process-wide instead of per thread, so a host that analyzes on several threads sees the one it installed.
- The bundled Tide catalogs are generated by opentide's own generator: `scripts/sync_opentide_schemas.py` runs `opentide.generation.lsp_catalog`, which `opentide generate schemas` also uses, instead of a copy of it ([#100](https://github.com/opentidehq/language-server/issues/100)). `--check` says whether the committed catalogs match, and a daily `opentide canary` job runs it against opentide's `development` branch, then the test suite against the catalogs it generates, without blocking. The router schema points each revision at its own schema (`rule::1.1` named `rule.1.0`).
- `@opentide/lsp-client` works on all three transports ([#14](https://github.com/opentidehq/language-server/issues/14)):
  - `stdio` keeps one `opentide-lsp --stdio` running and calls `opentide/analyze` and `opentide/highlight` over JSON-RPC;
  - `worker` calls the `opentide-wasm` module you load with `@opentide/lsp-worker`;
  - `wasi` runs the `wasm32-wasip1` CLI under `node:wasi`.

  Before, `analyze` always returned no diagnostics, `wasi` did nothing, and `legend()` was a hard-coded list that lacked `markdown.*` and `macro`. A transport that cannot answer now rejects, as does an unknown language id. The `worker` transport takes `module` instead of reading a global, and `wasi` takes the binary as `wasi`.

## [0.5.0] - 2026-10-26

The Elastic Security release: ES|QL, EQL, Kibana KQL, and Lucene rules get the same editing support as KQL and SPL, and the server installs from crates.io with `cargo install opentide-lsp`.

### Added

- ES|QL, EQL, Kibana KQL (kuery), and Lucene grammars, with highlighting, diagnostics, hover, completion, signature help, and injection into Tide rule queries ([#88](https://github.com/opentidehq/language-server/pull/88)).
- An Elastic Common Schema field catalog for the Elastic engines.
- Conformance against Elastic's own parsers, a live Elasticsearch reference from 8.19 through 9.5, and a sweep of the public Elastic detection rules in CI.
- Every crate is published to crates.io. Each GitHub Release carries a binary per target, named for it.

### Changed

- The workspace version is the release version; the internal crates are pinned to it.
- This repository no longer builds a Python wheel. The Python bindings, and the `opentide` command that wraps the server, live in [opentidehq/opentide](https://github.com/opentidehq/opentide).

## [0.4.0] - 2026-10-23

Differential oracles: every corpus query is checked against Microsoft's Kusto.Language and Splunk's own parser, and the grammar and catalog gaps they found are closed.

### Added

- Kusto.Language 12.4.1 and Splunk 10.6.1 oracles compared with opentide-lsp on every corpus query, external rule, Tide rule query, and catalog name; `testdata/oracles/exceptions.toml` records each known disagreement ([#87](https://github.com/opentidehq/language-server/pull/87)).
- KQL: named aggregates, multi-value lists, `between`, dynamic literals, member and index access, `mv-expand`, `mv-apply`, `make-series`, `evaluate`, `datatable`, operator options, tabular `let` and functions, `materialize` and `toscalar`. Every Sentinel rule in the corpus parses.
- KQL catalog: 32 functions and 17 plugins from Microsoft Learn; 15 deprecated aliases warn `kql_deprecated_function`.
- SPL: multiple aggregations, `tstats where` in search syntax, leading macros, boolean groups, and field lists; searchbnf aliases and `Risk.All_Risk`.
- A licence scan of every release artifact for oracle references.

### Changed

- Tide catalogs are generated from opentide 0.16.1 ([#75](https://github.com/opentidehq/language-server/pull/75)).
- The project is spelled opentide in lowercase, Opentide in class names ([#74](https://github.com/opentidehq/language-server/pull/74)).

### Fixed

- `evaluate` plugins are checked against the plugin catalog, and `let`-bound names are no longer flagged as unknown.
- `dedup` requires a field.

## [0.3.0] - 2026-09-29

Queries read like their vendor documentation: KQL and SPL signatures follow Microsoft Learn and the Splunk Search Reference, and slow query shapes warn.

### Added

- Warnings, with vendor citations, for slow public KQL and SPL shapes: a late `where`, unscoped `search` or `union`, wildcard tables, `join` or `summarize` before `project`, leading and mid-token wildcards, and truncating subsearches ([#61](https://github.com/opentidehq/language-server/pull/61)).
- SPL completion, hover, and signature help from Search Reference arguments ([#60](https://github.com/opentidehq/language-server/pull/60)).
- Standalone `.kql` and `.spl` files are first-class documents ([#59](https://github.com/opentidehq/language-server/pull/59)).
- Validation of Tide lists and of public KQL and SPL faults ([#53](https://github.com/opentidehq/language-server/pull/53)).
- Agent skills for the Rust, tree-sitter, and host stack ([#71](https://github.com/opentidehq/language-server/pull/71)).

### Changed

- KQL signatures and operator options follow each item's Microsoft Learn syntax, with parameter docs ([#62](https://github.com/opentidehq/language-server/pull/62)).

### Fixed

- Tide YAML keys keep one color at every nesting depth ([#58](https://github.com/opentidehq/language-server/pull/58)).

## [0.2.0] - 2026-09-24

Tide objects from the schemas: hover, completion, and highlighting come from the opentide 0.5.0 schema export, and deprecated fields warn.

### Added

- Tide fields resolved by schema family and YAML path, generated from opentide 0.5.0.
- Warnings on deprecated Tide fields, with a workspace overlay at `.opentide/lsp/catalogs/`.
- KQL Sentinel and Defender columns; SPL macros, CIM data models, and `tstats`; signature help.
- Markdown highlighting inside Tide description, analysis, and recommendation blocks.
- Folding, selection ranges, workspace symbols, code actions, inlay hints, and document highlights.
- Tag builds attach the highlights zip and native binaries to a GitHub Release.

### Fixed

- Incremental edits all apply, and closing a document clears its diagnostics.
- SPL `tstats` `as` and `where` are highlighted.

## [0.1.0] - 2026-09-16

The first working server: KQL, SPL, and Tide YAML over stdio and WASM, with the highlighting spec every editor shares.

### Added

- I/O-free KQL and SPL engines on vendored tree-sitter grammars, with catalogs from Microsoft Learn and the Splunk Search Reference.
- Tide YAML with the UUID graph and KQL and SPL injected into rule queries.
- A frozen HighlightSpec with generated editor maps, and semantic tokens on the standard LSP legend.
- Stdio and WASM hosts, and Zed, Helix, and Neovim samples.

[0.6.0]: https://github.com/opentidehq/language-server/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/opentidehq/language-server/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/opentidehq/language-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/opentidehq/language-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/opentidehq/language-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/opentidehq/language-server/releases/tag/v0.1.0
