# SPL language design (ES / CIM / ESCU)

Context base for the OpenTide SPL engine. Authored text is never rewritten
with an implicit `| search`. `index=main | head 1` stays `bare_search`.

Citations:

- [Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [tstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats)
- [Use search macros](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usesearchmacros)
- [CIM fields](https://docs.splunk.com/Documentation/CIM/latest/User/CIMfields)
- [CIM data models](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- [Search syntax](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutthesearchlanguage)

## Layers

| Layer | Source of truth | Runtime |
| --- | --- | --- |
| Commands / eval+stats functions | `catalogs/spl/commands.toml` | hover / completions / unknown-command |
| **CIM + default fields** | `catalogs/spl/fields.toml` | hover / completions after `by` / `where` / `table` |
| **Data models** | `catalogs/spl/datamodels.toml` | `from datamodel=`; prefixed fields |
| **Macros** | `catalogs/spl/macros.toml` | `` `drop_dm_object_name` `` hover + completion |
| **Command options** | `catalogs/spl/command-options.toml` | `tstats summariesonly=`; signature help |
| Grammar | `grammars/tree-sitter-opentide-spl` | macros ≠ comments; dotted fields; subsearches |
| HighlightSpec | `highlights/spec.toml` | `macro` capture (added in 0.2.0) |

CrowdStrike is unrelated. Control/app commands (`dbxquery`, …) stay out of v1.

## Macros vs comments (hard rule)

| Syntax | Meaning | Capture |
| --- | --- | --- |
| `` ```comment``` `` | comment (three backticks both sides) | `comment` |
| `` `macro` `` / `` `macro(args)` `` | search macro | `macro` |

Single-backtick pairs are **never** comments. The grammar must not fold
macros into `comment`. The language server does **not** expand macros.

ESCU detections commonly look like:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("cmd.exe","powershell.exe")
    by Processes.dest, Processes.user, Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

Leading `|` before a generating command (`tstats`, `from`, a generating
macro) is legal authored text.

## CIM data models

`datamodels.toml` maps `Model.Dataset` → field prefix used **before**
`` `drop_dm_object_name(Dataset)` ``:

| `datamodel=` | Prefix | Critical fields |
| --- | --- | --- |
| `Endpoint.Processes` | `Processes.` | `process_name`, `process`, `user`, `dest`, `parent_process_name` |
| `Endpoint.Filesystem` | `Filesystem.` | `file_name`, `file_path`, `dest` |
| `Endpoint.Registry` | `Registry.` | `registry_path`, `registry_value_name`, `dest` |
| `Authentication.Authentication` | `Authentication.` | `user`, `src`, `dest`, `action`, `app` |
| `Network_Traffic.All_Traffic` | `All_Traffic.` | `src`, `dest`, `src_port`, `dest_port`, `action` |
| `Web.Web` | `Web.` | `url`, `http_user_agent`, `src`, `dest` |
| `Intrusion_Detection.IDS_Attacks` | `IDS_Attacks.` | `signature`, `src`, `dest`, `severity` |
| `Malware.Malware_Attacks` | `Malware_Attacks.` | `file_name`, `file_hash`, `dest`, `user` |
| `Change.All_Changes` | `All_Changes.` | `object`, `action`, `status`, `user` |
| `Network_Resolution.DNS` | `DNS.` | `query`, `answer`, `src` |

Hover on `Processes.user` resolves as field `user` on dataset `Processes`
(or unprefixed `user` after the drop macro). Completions after
`from datamodel=` offer model paths; after `by ` in a `tstats` they offer
the prefixed field set for the active datamodel.

## `tstats` option schema

```
tstats [summariesonly=] [prestats=] [allow_old_summaries=] [fillnull_value=]
       aggregates
       [from datamodel=Model.Dataset]
       [where predicate]
       [by fields]
```

`summariesonly` is often supplied by `` `security_content_summariesonly` ``
rather than a literal `summariesonly=t`.

## Search-clause forms

Inside `search` / `bare_search` (not only `eval` comparisons):

- `field=value`, quoted strings, bare terms
- `field IN (a, b, c)`
- `TERM(value)` / `CASE(value)`
- boolean `AND` `OR` `NOT`
- subsearch `[ pipeline ]` anywhere a term is allowed (not only `join`)

## Signature help

| Trigger | Label |
| --- | --- |
| `tstats` | aggregates + `from datamodel=` + `where` + `by` |
| `stats` / `eventstats` | aggregations + `by` |
| `eval` function `(` | catalog function signature |
| `` `macro( `` | macro signature |

## Highlight overlay

After tree-sitter:

- catalog functions → `function.builtin`
- catalog commands (including `from` / `by` / `AS`) → `keyword`
- CIM / default fields and `Dataset.field` → `property`
- datamodel paths → `type`
- macros → `macro` (never `comment`)
- `Processes.user` must not paint as `error`

## Related

- [cim-fields.md](cim-fields.md) — field inventory
- [macros.md](macros.md) — ESCU / ES macros
- [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md)
- [search-syntax.md](search-syntax.md)
