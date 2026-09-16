# SPL search macros

Macros are knowledge objects that expand to SPL fragments before the search runs. They are ubiquitous in Splunk ES / ESCU detections.

Citations:

- [Use search macros in searches](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usesearchmacros)
- [Search macro definition](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Definesearchmacros)
- [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search)

## Authored form

Macros are written with **single backticks**:

```spl
`macro_name`
`macro_name(arg1, arg2)`
```

- Names are typically `snake_case` (do **not** hyphenate).
- Arguments are comma-separated inside `(...)`.
- Expansion is textual: the macro body is spliced into the search string, then the search is parsed.

**Comments** use **three** backticks on each side (`` ```comment``` ``). Single-backtick pairs are **never** comments.

## Pipe placement

If a macro expands to a **generating** command (`tstats`, `from`, `inputlookup`, `makeresults`, …), the authored query must place a pipe **before** the macro:

```spl
| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes
    by Processes.dest
```

```spl
| `cim_Endpoint_indexes` earliest=-1h
| stats count by dest
```

(Exact expansion of index macros varies by ESCU/ES content pack.)

## Escaping / nesting

- Nested macros are allowed: a macro body may contain further `` `inner` `` calls.
- Inside a macro body, `$arg$` (or named tokens depending on definition) is replaced by arguments.
- Quote arguments that contain spaces or commas.

## ES / ESCU macros commonly seen in detections

| Macro | Typical role |
| --- | --- |
| `` `security_content_summariesonly` `` | Expands to a `summariesonly=` / related `tstats` flag |
| `` `security_content_ctime(field)` `` | Formats a time field for notable display |
| `` `drop_dm_object_name(Dataset)` `` | Strips `Dataset.` prefixes after `tstats` |
| `` `cim_Authentication_indexes` `` | Index allow-list for Authentication |
| `` `cim_Network_Traffic_indexes` `` | Index allow-list for Network Traffic |
| `` `cim_Endpoint_indexes` `` | Index allow-list for Endpoint |
| `` `cim_Web_indexes` `` | Index allow-list for Web |
| `` `cim_Intrusion_Detection_indexes` `` | Index allow-list for IDS |
| `` `get_asset(dest)` `` / `` `get_identity(user)` `` | Asset / identity enrichment |
| `` `notable` `` / `` `get_risk` `` | ES notable / risk plumbing (response path) |

Exact names vary by app version; treat this table as a recognition aid for OpenTide `splunk.query` bodies, not as a closed catalog.

## OpenTide engine notes

- Authored backticks must remain in the source (no macro expansion in the language server).
- Grammar today folds some single-backtick spans into `comment` — that is an implementation gap (see [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md)).
- There is no macro-name completion catalog yet.

## Detection examples

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("cmd.exe","powershell.exe")
    by Processes.dest, Processes.user, Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

```spl
`cim_Authentication_indexes` action=failure
| stats count by src, user
| where count > 20
```
