# kql_table_misspelt

A KQL table is not one the engine knows or the workspace declares, but is a near miss of one that is (one edit for a name of up to seven characters, two for a longer one, and not a custom `_CL` table): most likely a typo.

Severity: error. Reported by the analysis engine in a KQL query under `sentinel`, at the table's name: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; an editor running `opentide lsp start` shows it too. It never applies to a `_CL` table, to a `let` binding or a function the engine knows, or to a name further from every known table than the bound: those are `kql_unknown_table`, a warning, because a Sentinel workspace holds tables and functions no catalog lists (`Sysmon` is a parser function two edits from `Syslog`, so it is not reported here). A match that differs only in case, `_`, `-` or spaces counts as no edit at all, so `SIGNINLOGS` is reported. Under `defender_for_endpoint` an unknown table is already an error, `kql_unknown_table`, with the same suggestion.

The nearest table comes from the tables the workspace declares in visibility.toml first, then from the engine's catalog. Only a name a query can write bare (`[A-Za-z_][A-Za-z0-9_]*`) is suggested: a declared display name such as `Azure Activity` is never offered.

## Example

```kusto
SecurityEvnt   // one letter from SecurityEvent
| where EventID == 4625
```

## How to fix

Correct the name to the table in the message (`did you mean 'SecurityEvent'?`). If the workspace really holds a table or function by that name, declare it as a log source in `visibility.toml` so it is known (the editor offers this as a quick fix), or run `opentide validate --queries warn` to report it as a warning:

```toml
[[logsources]]
name = "SecurityEvnt"
description = "A workspace table whose name is this close to a known one."
system = "sentinel"
```
