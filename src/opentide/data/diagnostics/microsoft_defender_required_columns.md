# microsoft_defender_required_columns

A Microsoft Defender query's output lacks a column a custom detection needs.

Severity: error. Reported by the analysis engine on a `microsoft_defender` block's `query` (microsoft-defender-1.0), at its last operator: `opentide validate` and `opentide lint` (their `queries` check) and an editor running `opentide lsp start` show it, without a tenant. A custom detection's results need `Timestamp`; `DeviceId` and `ReportId` when the query reads a device table (`DeviceProcessEvents`, `DeviceEvents`, ...); `ObservationId` for an observation table; `ReportId` for the other Defender XDR tables, with a column that identifies the impacted asset (`AccountUpn`, `RecipientEmailAddress`, `DeviceName`, ...); and `Timestamp` or `TimeGenerated`, `ReportId` and an asset column when the query reads none of them. It is the offline twin of the check `opentide validate query --live` makes on the columns the tenant returns, from the same table. The engine reports it only when the query names its output columns (a query names its columns once a `project`, a `project-keep` without a pattern, a `summarize` (one without `arg_max(..., *)` or `arg_min(..., *)`, which copies a table's columns), `distinct` or `count` sets them and nothing after it adds a column the engine cannot name): otherwise the query returns every column of its tables. Offline, the table family is read from the Defender XDR tables the query names anywhere, a `join`, a `union` or a `let` included, as the live check reads it; a query that names none of them (only a custom table, a function, `datatable`) gets nothing offline, and its columns are checked by `opentide validate query --live`. A table named only in a `let` the query does not use still counts. When the engine cannot infer the output, nothing is reported.

## Example

```yaml
configurations:
  microsoft_defender:
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe"
      | project Timestamp, AccountUpn   # lacks DeviceId and ReportId
```

## How to fix

Keep the columns the message names in the query's output: `| project Timestamp, ReportId, DeviceId, AccountUpn`.
