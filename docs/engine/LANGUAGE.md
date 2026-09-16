# Languages

SQL is out of scope. There is no `opentide-sql`.

## KQL

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| kql.let | `let_statement` | `let_statement__valid`, `let_statement__invalid` | `keyword` |
| kql.where | `where_operator` | `where_operator__valid` | `keyword` |
| kql.project | `project_operator` | `project_operator__valid` | `keyword` |
| kql.project-away | `project_away_operator` | `project_away_operator__valid` | `keyword` |
| kql.project-rename | `project_rename_operator` | `project_rename_operator__valid` | `keyword` |
| kql.extend | `extend_operator` | `extend_operator__valid` | `keyword` |
| kql.summarize | `summarize_operator` | `summarize_operator__valid` | `keyword` |
| kql.join | `join_operator` | `join_operator__valid` | `keyword` |
| kql.union | `union_operator` | `union_operator__valid` | `keyword` |
| kql.parse | `parse_operator` | `parse_operator__valid` | `keyword` |
| kql.lookup | `lookup_operator` | `lookup_operator__valid` | `keyword` |
| kql.take | `take_operator` | `take_operator__valid` | `keyword` |
| kql.limit | `limit_operator` | `limit_operator__valid` | `keyword` |
| kql.sort | `sort_operator` | `sort_operator__valid` | `keyword` |
| kql.distinct | `distinct_operator` | `distinct_operator__valid` | `keyword` |
| kql.render | `render_operator` | `render_operator__valid` | `keyword` (warning `kql_render_not_valid`) |
| kql.control | `control_command` | `control_command__valid` | `error` (`kql_control_command_unsupported`) |
| kql.pipe | `"\|"` | `take_operator__valid` | `operator.pipe` |
| kql.function | `function_call` | `function_call__valid` | `function` |
| kql.string | `string` | `string__valid` | `string` |
| kql.number | `number` | `number__valid` | `number` |
| kql.comment | `comment` | `comment__valid` | `comment` |

Control commands are parsed so the engine can reject them. They are not valid detections.

## SPL

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| spl.bare | `bare_search` | `bare_search__valid` | `property` |
| spl.search | `search_command` | `search_command__valid` | `keyword` |
| spl.where | `where_command` | `where_command__valid` | `keyword` |
| spl.eval | `eval_command` | `eval_command__valid` | `keyword` |
| spl.stats | `stats_command` | `stats_command__valid` | `keyword` |
| spl.rex | `rex_command` | `rex_command__valid` | `keyword` |
| spl.table | `table_command` | `table_command__valid` | `keyword` |
| spl.rename | `rename_command` | `rename_command__valid` | `keyword` |
| spl.fields | `fields_command` | `fields_command__valid` | `keyword` |
| spl.dedup | `dedup_command` | `dedup_command__valid` | `keyword` |
| spl.sort | `sort_command` | `sort_command__valid` | `keyword` |
| spl.head | `head_command` | `head_command__valid` | `keyword` |
| spl.tail | `tail_command` | `tail_command__valid` | `keyword` |
| spl.join | `join_command` | `join_command__valid` | `keyword` |
| spl.lookup | `lookup_command` | `lookup_command__valid` | `keyword` |
| spl.makemv | `makemv_command` | `makemv_command__valid` | `keyword` |
| spl.mvexpand | `mvexpand_command` | `mvexpand_command__valid` | `keyword` |
| spl.tstats | `tstats_command` | `tstats_command__valid` | `keyword` |
| spl.unknown | `unknown_command` | `unknown_command__valid` | `error` (`spl_unknown_command`) |
| spl.pipe | `"\|"` | `head_command__valid` | `operator.pipe` |

Authored text is tokenized as written. An implicit leading `| search` is a Splunk runtime default, not a rewrite of the source.

Corpus lives in `testdata/corpus/{kql,spl}/` tagged `prod:<rule>`.
