# SPL search syntax

Syntax used in Splunk ES detections and opentide `splunk.query` blocks. Citations are Search Reference / Search Manual pages under `docs.splunk.com`.

Primary citations:

- [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search)
- [Understanding SPL syntax](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/UnderstandingSPLsyntax)
- [Boolean expressions with logical operators](https://docs.splunk.com/Documentation/Splunk/latest/Search/Booleanexpressions)
- [Use search macros](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usesearchmacros)
- [Add comments to searches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Addcommentstosearches)
- [About subsearches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsubsearches)

## Implicit `search`

A pipeline that does **not** start with another generating command is executed as an implied `search`. Authored source is **not** rewritten (see [README.md](README.md)).

```spl
index=wineventlog EventCode=4688 process_name=powershell.exe
```

is equivalent at runtime to:

```spl
search index=wineventlog EventCode=4688 process_name=powershell.exe
```

Generating commands that **replace** implied search must be written with a leading pipe: `| tstats …`, `| makeresults`, `| inputlookup …`, `| from …`, `| rest …`, `| metadata …`.

Without the pipe Splunk accepts the query and searches for the words: `tstats count where index=a by sourcetype` runs `search tstats count where index=a by sourcetype` and returns nothing. The engine parses it as search terms, as Splunk does, and reports `spl_command_without_pipe` (error) when the first word is a catalogued command followed by two or more terms; the fix adds `| `. A lone word (`error`, `tstats`) or a command word with one term (`delete user`) may be a real search and is not reported. A subsearch is different: Splunk runs a leading command word there as the command (`[makeresults | eval a=1]`, `[inputlookup t.csv]`).

Citation: [search — The implied search command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search).

## Field-value pairs

```
field=value
field!=value
field>n  field>=n  field<n  field<=n
field IN (v1, v2, v3)
NOT field IN (v1, v2)
```

- `=` and `!=` compare **strings** (`"1"` does not match `"1.0"`).
- `< > <= >=` compare numbers numerically; other values lexicographically (UTF-8).
- To compare **two fields**, use `where`, not `search`: `| where src_ip=dest_ip`.
- Quote values that contain spaces, commas, pipes, brackets, equals, or reserved words (`AND`, `OR`, `NOT`, `IN`, `AS`).
- Field names with non-alphanumerics (other than `_`) need single quotes in `eval`/`where`: `'process-name'`.

Citation: [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search), [Field expressions](https://docs.splunk.com/Documentation/Splunk/latest/Search/Fieldexpressions).

### Default indexed fields

These are first-class search modifiers (not just ordinary extracted fields):

| Specifier | Example | Notes |
| --- | --- | --- |
| `index=` | `index=wineventlog` | Restrict to one or more indexes (`index=a OR index=b`, wildcards) |
| `sourcetype=` | `sourcetype=WinEventLog:Security` | Source type |
| `source=` | `source="*Security.evtx"` | Originating file / input |
| `host=` | `host=dc01*` | Originating host |
| `splunk_server=` | `splunk_server=local` | Search peer; `local` = search head |
| `eventtype=` | `eventtype=malware` | Event type |
| `tag=` / `tag::field=` | `tag=authentication` | Knowledge-object tags |
| `savedsearch=` | rarely in detections | Events a saved search would find |

Bare keywords (no `field=`) search `_raw`.

Citation: [search — Index expression options](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search).

## Quoted strings

- Phrases: `"failed password"`.
- Quote values with breaking characters (space, comma, `|`, `[ ]`, `=`).
- Quote reserved words used as values: `country="IN"`, `state="OR"`.
- Escape inside quotes: `\"`, `\\`, `\|`. Unrecognized sequences such as `\s` are passed through.

```spl
index=web status=404 "login failed"
src_user="j doe"
process_name="C:\\Windows\\System32\\cmd.exe"
```

Citation: [search — Quotes and escaping characters](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search).

## Boolean operators

Operators **must be capitalized**: `AND`, `OR`, `NOT`. `XOR` exists for `eval`/`where` only; `search` does not support `XOR`.

`AND` is always implied between terms: `web error` ≡ `web AND error`.

Evaluation order **differs** by command:

| Order | `search` (and implied search) | `eval` / `where` |
| --- | --- | --- |
| 1 | Parentheses | Parentheses |
| 2 | `NOT` | `NOT` |
| 3 | `OR` | `AND` |
| 4 | `AND` | `OR` |
| 5 | — | `XOR` |

```spl
(EventCode=4688 OR EventCode=1) dest=workstation* NOT user=SYSTEM
```

`NOT field=value` is not the same as `field!=value`:

| Expression | Meaning |
| --- | --- |
| `NOT fieldA="value2"` | Everything except that pair, including events where `fieldA` is absent |
| `fieldA!="value2"` | `fieldA` exists and is not `"value2"` |
| `NOT fieldA=*` | `fieldA` is null / undefined |
| `fieldA!=*` | Never matches |

Citation: [Boolean expressions with logical operators](https://docs.splunk.com/Documentation/Splunk/latest/Search/Booleanexpressions), [search — Using the NOT or != comparisons](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search).

## Wildcards

`*` matches zero or more characters in `search` (not in `eval` `in()`).

```spl
host=webserver*
status IN (4*, 5*)
process_name=*.exe
```

Leading wildcards (`*password*`) force scans of `_raw` and are expensive. `TERM()` forces a single indexed term; `CASE()` makes a term case-sensitive.

CIDR matching works on IPv4/IPv6 fields: `src_ip="10.0.0.0/8"`. Equivalent eval: `cidrmatch("10.0.0.0/8", src_ip)`.

Citation: [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search).

## Time modifiers

Common in detections (often also set on the saved search / correlation search, not only in SPL):

```
earliest=-24h@h latest=now
earliest=-15m
```

`@h` snaps to the hour. `now` is search-start time. Relative specifiers: `s`, `m`, `h`, `d`, `w`, `mon`, `y`.

Citation: [Time modifiers](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchTimeModifiers).

## Pipes

`|` sends the current result set to the next command. Transforming commands (`stats`, `chart`, `timechart`, `table`, `top`, `rare`) drop `_raw` unless preserved earlier.

```spl
index=web status>=400
| eval uri=lower(uri)
| stats count by dest, status
| where count > 10
```

Citation: [search](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search) — “Use the vertical bar (`|`) to apply a command”.

### Forms Splunk accepts that are mistakes

`spl_parse_error` means Splunk's parser rejects the query. Checked against Splunk 10.6.1 (`search/parser` with `parse_only=t`, and as a real search), these forms parse and get their own code instead:

| Form | Splunk | Diagnostic |
| --- | --- | --- |
| `\| where`, `\| search`, `\| fields`, `\| eventstats`, `\| streamstats`, `\| sistats`, `\| lookup` with no arguments | runs; keeps every row (`sistats` returns one summary row) | `spl_empty_command` (warning) |
| `\| stats` with no arguments | runs; returns no results | `spl_empty_command` (error) |
| `\| inputlookup` with no table, first in the search | runs; fails: the lookup table `''` needs a definition | `spl_empty_command` (error) |
| `… \| stats count \|` | ignores the empty last stage | `spl_empty_stage` (warning) |
| `tstats count where index=a by sourcetype` (no leading `\|`) | searches for the words, returns nothing | `spl_command_without_pipe` (error, with a fix) |

Splunk also parses `==`, `<>`, `=>`, `=<` and `!~` in a search (`status==200`, `status == 200`, even `a==` or `==1`) and in `inputlookup ... where`, but splits each into separate terms (`status == 200`), so the comparison never matches. They parse here too; `tstats ... where` rejects them ("WHERE clause is not an exact query"), and so does the engine (`spl_parse_error`). `x=~1` is `=` with the value `~1`. A `|` ends the stage even inside an open `(` or `TERM(` (`TERM(x|y)` runs a command `y)`), but not inside quotes, comments, macros or a subsearch's `[ ]`.

`head`, `spath`, `fillnull`, `tojson` and `tail` have defaults and are not reported. Splunk rejects, and the engine reports `spl_parse_error` for: an empty stage before another (`… \| \| stats count`) or at the end of a subsearch (`[search a \|]`), `inputlookup` with no table later in a pipeline, `\| index=a`, and these commands with no arguments: `chart`, `timechart`, `sichart`, `sitimechart`, `geostats`, `foreach`, `outputlookup`, `sort`, `rename`, `dedup`, `table`, `eval`, `rex`, `mvexpand`, `makemv`, `join`, `append`, `top`, `rare`, `transaction`, `bin`, `tstats`, and other catalogued commands Splunk requires arguments for (`xyseries`, `regex`, `iplocation`, `rest`, `metadata`, …). Unbalanced parentheses are a syntax error at the parenthesis (`unbalanced parentheses: this ')' has no matching '('`); an unclosed `TERM(x` is not, since Splunk matches it like `TERM(x)`.

## Subsearches `[ ]`

See the dedicated inventory: [subsearches.md](subsearches.md).

Square brackets run a **subsearch** first. The subsearch must start with a generating command (`search` is implied inside the brackets if the first token is not generating). Results are typically formatted into a parenthesized `OR` clause, or consumed by `join` / `append` / `return`.

```spl
index=web
  [ | inputlookup blocked_ips.csv | fields src_ip | format ]
```

```spl
index=auth action=failure
| join type=inner user
    [ search index=auth action=success | stats count by user ]
```

Limits: `maxout` (default 10000 for `join`/`append` contexts; `return` defaults to 1), `maxtime`, `timeout`. Subsearches that return zero events can silently widen or empty the parent search.

`return` emits `search` terms from a subsearch:

```spl
[ search index=notable | head 1 | return dest ]
```

Citation: [About subsearches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsubsearches), [return](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Return), [format](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Format).

## Macros `` `macro` ``

See the dedicated inventory: [macros.md](macros.md).

Backticks expand a saved search macro. Arguments: `` `macro(arg1,arg2)` ``.

```spl
| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes
    where Processes.process_name=cmd.exe by Processes.dest
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
```

ES / ESCU macros commonly seen in detections:

| Macro | Role |
| --- | --- |
| `` `security_content_summariesonly` `` | Expands to `summariesonly=` flag for `tstats` |
| `` `drop_dm_object_name(Process)` `` | Strips `Processes.` / dataset prefix after `tstats` |
| `` `security_content_ctime(field)` `` | Human-readable time via `eval`/`convert` |
| `` `cim_Authentication_indexes` `` | Index allow-list for a CIM datamodel |
| `` `cim_Network_Traffic_indexes` `` | Same for Network Traffic |
| `` `cim_Endpoint_indexes` `` | Same for Endpoint |
| `` `get_asset(dest)` `` | Asset lookup enrichment |
| `` `get_risk` `` / `` `notable` `` | ES notable / risk plumbing (response, not detection body) |

If a macro expands to a generating command (`tstats`, `from`, `inputlookup`, …), put a pipe **before** the macro.

Do not hyphenate macro names (`macro_name`, not `macro-name`).

Citation: [Use search macros in searches](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usesearchmacros).

## Comments

See the dedicated inventory: [comments.md](comments.md).

Inline comments use **three backticks** on each side:

```spl
index=web ```only 4xx/5xx``` status>=400
| stats ```volume by dest``` count by dest
```

The processor replaces comments with a **space** (so `stats```x```count` becomes `stats count`, not `statscount`).

Limitations:

- Do not put a comment **before** a generating command (`tstats`, `makeresults`, `multisearch`, `gentimes`) — the search fails or misparses.
- Comments inside quoted strings are **not** comments.
- Backslash does not escape comment delimiters.

Citation: [Add comments to searches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Addcommentstosearches).

Single-backtick pairs are **macros**, not comments. Triple-backtick pairs are comments.

## `eval` / `where` expression syntax (vs `search`)

| Topic | `search` | `eval` / `where` |
| --- | --- | --- |
| Equality | `status=200` | `status==200` |
| Strings | optional quotes | double quotes required for literals |
| Field names with punctuation | `field=…` | `'field-name'` |
| Booleans | `AND` implied, `OR` before `AND` | `AND` before `OR`, `XOR` allowed |
| Wildcards | `*` | `like()`, `match()`, `in()` (no `*` in `in()`) |
| CIDR | `ip="10.0.0.0/8"` | `cidrmatch("10.0.0.0/8", ip)` |
| Concatenation | n/a | `+` |
| Nulls | `NOT field=*` | `isnull(field)` / `isnotnull(field)` |

Citation: [eval](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eval), [where](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Where).

## `tstats` WHERE / BY (detection dialect)

```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("cmd.exe","powershell.exe")
          Processes.dest=*
    by Processes.dest, Processes.user, Processes.process_name
```

- `from datamodel=Model.RootDataset`
- Filter with `where` (lowercase in `tstats`, not `WHERE` required but accepted)
- `IN (...)` is common for process names / EventCodes
- `by` groups; `span=` bins `_time`
- CIM fields are prefixed with the dataset name until `` `drop_dm_object_name` ``

Citation: [tstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats).

## IN operator

`search` / `tstats`:

```spl
EventCode IN (4688, 1, 4104)
process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe")
error IN (40*)
```

`eval` / `where` function form (no wildcards in the value list):

```spl
| where in(status, 400, 401, 403, 404, 500)
```

Citation: [search — Filter using the IN operator](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search), [in (eval)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ConditionalFunctions).
