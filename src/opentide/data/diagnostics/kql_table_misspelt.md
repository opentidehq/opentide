# kql_table_misspelt

A KQL table is not one the engine knows or the workspace declares, but its name is within two edits of one that is (ASCII case ignored), so it is most likely a typo.

Severity: error. Reported by the analysis engine on a KQL query under `sentinel`: `opentide validate`, `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it, and `opentide validate` fails on it. A table that ends in `_CL` (a custom table) is never reported here, and neither is a name three or more edits from every known table: those stay `kql_unknown_table`, a warning, because a Sentinel workspace holds tables no catalog lists. Under `defender_for_endpoint` an unknown table is already an error, `kql_unknown_table`, with the same suggestion.

The nearest table is taken from the tables the workspace declares in visibility.toml first, then from the engine's catalog. Only a name a query can write bare (`[A-Za-z_][A-Za-z0-9_]*`) is suggested: a declared display name such as `Azure Activity` is never offered.

## Example

```kusto
SecurityEvnt   // two letters from SecurityEvent
| where EventID == 4625
```

## How to fix

Correct the name to the table in the message (`did you mean 'SecurityEvent'?`). If the name is right and the workspace holds a table by that name, declare it in `visibility.toml` so it is known, or lower the code for the workspace in `lint.toml`:

```toml
[queries.codes]
kql_table_misspelt = "warning"
```

```toml
[[logsources]]
name = "SecurityEvnt"
description = "A workspace table whose name is this close to a known one."
system = "sentinel"
```
