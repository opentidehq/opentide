# SPL subsearches

Subsearches run an inner pipeline and feed its results into the outer search (as filter terms, join rows, appended rows, or returned field values).

Citations:

- [About subsearches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsubsearches)
- [Use subsearches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Usesubsearchtocorrelateevents)
- [return](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Return)
- [format](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Format)
- [join](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Join)
- [append](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Append)

## Authored form

Square brackets delimit a subsearch:

```spl
index=web
  [ | inputlookup blocked_ips.csv | fields src_ip | format ]
```

Rules of thumb:

1. The subsearch runs **first**.
2. If the first token inside `[` is not a generating command, Splunk implies `search` **inside the subsearch only** — that is still a runtime default, not an OpenTide source rewrite of the outer query.
3. Leading `|` inside the brackets is common when the subsearch starts with an explicit generating command (`| inputlookup`, `| makeresults`, `| tstats`).
4. Outer authored text that begins `index=...` remains a `bare_search` in OpenTide.

## Result shaping

| Pattern | Behavior |
| --- | --- |
| Bare `[ search ... ]` | Results formatted into `(field=value OR …)` and AND-ed into the outer search |
| `\| format` | Explicit `(f=v OR f=v)` shaping |
| `\| return field` / `\| return $1` | Emits `field=value` terms (default `count=1`) |
| `\| join … [ … ]` | Row join on fields |
| `\| append [ … ]` | Append rows |
| `\| appendcols [ … ]` | Bind columns by position |
| `\| appendpipe [ … ]` | Run a subpipeline on the **current** result set and append |
| `\| map [ … ]` / `map search=` | Per-row template execution (expensive; rare in ES) |

## Limits

| Knob | Typical default / note |
| --- | --- |
| `maxout` | Often 10000 for join/append contexts; `return` defaults to 1 |
| `maxtime` / `timeout` | Subsearch wall clock |
| Zero results | Can silently empty or widen the outer search depending on usage |
| Nested depth | Practical nesting is shallow; deep nesting is discouraged in detections |

## Detection patterns

Watchlist / denylist filter:

```spl
index=proxy
  [ | inputlookup bad_domains.csv | fields domain | format ]
| stats count by src, domain
```

Join successes to failures:

```spl
index=auth action=failure
| join type=inner user
    [ search index=auth action=success | stats count by user ]
```

Return a single pivot value:

```spl
index=firewall dest=
  [ search index=notable | head 1 | return dest ]
```

Multisearch-style parallelism uses the `multisearch` **command** with multiple bracketed streaming legs (see [commands.md](commands.md)), which is related but not the same as a filter subsearch.

## OpenTide engine notes

- Grammar parses a nested `pipeline` inside `join … [ … ]` only.
- Other `[` `]` pairs are punctuation tokens today — inner commands are **not** fully analyzed as a nested pipeline (implementation gap).
- Do not rewrite outer `bare_search` when documenting or implementing subsearch analysis.

## Related

- [macros.md](macros.md) — backticks, not brackets
- [search-syntax.md](search-syntax.md) — booleans / `IN` / pipes
- [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md) — parser punch list
