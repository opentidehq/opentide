# kql_table_not_declared

The table is one the engine knows for the platform, but no log source of the workspace declares it in visibility.toml.

Severity: warning. Reported by the analysis engine on a KQL query (`sentinel`, `defender_for_endpoint`): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in per system: only a workspace whose `visibility.toml` has at least one log source for that platform gets it. It applies to a table the engine's catalog knows (a built-in table such as `SigninLogs`) that no log source names; a table the catalog does not know and no log source names is `kql_unknown_table` instead. Every name a query reads from counts (a pipeline's first source, a `union` leg, a `join` or `lookup` right side), whatever its case, except a `let` binding, a query parameter or a function the engine knows, so a workspace function is declared as a log source too. `*` in a declared name matches any run of characters.

## Example

```toml
[[logsources]]
name = "NTANetAnalytics"
description = "Traffic analytics on the production VNet flow logs."
system = "sentinel"
```

```kusto
NTAIpDetails   // known to the engine, not declared for sentinel
| where FlowType == "MaliciousFlow"
```

## How to fix

Correct the table name, or declare it: add a log source whose `name` is the table (or a pattern such as `*_CL` that covers it) in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).

```toml
[[logsources]]
name = "NTAIpDetails"
description = "IP details from traffic analytics."
system = "sentinel"
```
