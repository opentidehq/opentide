# kql_table_not_declared

The table is not one the workspace declares in visibility.toml for the platform.

Severity: warning. Reported by the analysis engine on a KQL query (`sentinel`, `defender_for_endpoint`): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in: only a workspace whose `visibility.toml` names at least one table for that platform gets it, for a table the engine does not otherwise know. `*` in a declared name matches any run of characters.

## Example

```toml
[[logsources]]
name = "VNet flow logs"
description = "Traffic analytics on the production VNet flow logs."
system = "sentinel"
tables = ["NTANetAnalytics"]
```

```kusto
NTAIpDetails   // not declared for sentinel
| where FlowType == "MaliciousFlow"
```

## How to fix

Correct the table name, or add it (or a pattern such as `*_CL`) to the `tables` of the log source that fills it in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).
