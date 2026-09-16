# SPL comments

Splunk search comments are literal text ignored by the search processor. They appear in hand-written detections and in macros.

Citation: [Add comments to searches](https://docs.splunk.com/Documentation/Splunk/latest/Search/Addcommentstosearches)

## Authored form

Comments use **three backticks** on each side:

```spl
index=web ```only 4xx/5xx``` status>=400
| stats ```volume by dest``` count by dest
```

The processor replaces each comment with a **space**, so:

```spl
| stats```x```count by dest
```

becomes `| stats count by dest` (not `| statscount`).

## Macros vs comments

| Form | Meaning |
| --- | --- |
| `` `macro` `` / `` `macro(a,b)` `` | **Macro** expansion |
| `` ```comment``` `` | **Comment** |

Never treat a single-backtick pair as a comment.

## Limitations (Splunk behavior)

1. Do **not** place a comment immediately **before** a generating command (`tstats`, `makeresults`, `multisearch`, `gentimes`, `inputlookup`, …) — the search fails or misparses.
2. Text inside quoted strings is **not** a comment.
3. Backslash does **not** escape comment delimiters.
4. Prefer short comments; they are for humans, not control flow.

## Safe placement in detections

```spl
index=wineventlog EventCode=4688 ```process create```
| eval process_name=lower(process_name)
| stats ```unique dest/user pairs``` count by dest, user, process_name
```

```spl
| tstats count from datamodel=Endpoint.Processes
    where Processes.process_name=cmd.exe
    by Processes.dest
| `drop_dm_object_name(Processes)` ```CIM prefix strip```
```

## OpenTide engine notes

- Authored comments must remain in the source buffer (no stripping before highlight/analyze unless a future pipeline documents it).
- Current grammar `comment` token incorrectly accepts `` ``` `` + rest-of-line **or** a single-backtick pair — that collides with macros and does not match Splunk’s paired `` ```…``` `` form. Tracked in [IMPLEMENTATION-GAPS.md](IMPLEMENTATION-GAPS.md).

## Related

- [macros.md](macros.md)
- [search-syntax.md](search-syntax.md)
