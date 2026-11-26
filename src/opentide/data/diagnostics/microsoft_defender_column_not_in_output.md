# microsoft_defender_column_not_in_output

A column a Microsoft Defender block names is not a column of its query's output.

Severity: error. Reported by the analysis engine on a `microsoft_defender` block (microsoft-defender-1.0), with its query's findings: `opentide validate` and `opentide lint` (their `queries` check) and an editor running `opentide lsp start` show it, without a tenant. Every column the block names is a column of what the query returns: an `entities` field, an action's column (not `isolation_type` or `device_groups`), an `alert.custom_details` value, and a `{{Column}}` placeholder in `alert.title` or `alert.description`. A column the query does not return cannot be filled from its results: Defender refuses the rule at deploy, or maps nothing. Column names compare as KQL's do: case-sensitively, so `deviceid` is not `DeviceId`. The finding is on the field (on the placeholder, in a title or description), with the output column it most likely means; an editor offers to replace it.

The engine infers the output offline: the columns after the query's last operator. A query names its columns once a `project`, a `project-keep` without a pattern, a `summarize` (one without `arg_max(..., *)` or `arg_min(..., *)`, which copies a table's columns), `distinct` or `count` sets them and nothing after it adds a column the engine cannot name; any other name is then reported. Otherwise the query returns every column of its tables, and a table can have columns its reference does not list yet: only a near miss of a documented column is reported then (`DevicId`). When the engine cannot infer the output (a table or function it does not know, an `evaluate` plugin, `bag_unpack`, an expression whose column name it does not model, a `union` with such a leg, several tabular statements), nothing is reported. `opentide validate query --live` checks what the tenant returns.

## Example

```yaml
configurations:
  microsoft_defender:
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe"
      | project Timestamp, ReportId, DeviceId, AccountUpn
    alert:
      title: Encoded PowerShell on {{DeviceName}}   # not projected
    entities:
      hosts:
        - device_id: DevicId                         # did you mean DeviceId?
```

## How to fix

Name a column the query returns, spelled as it is (`device_id: DeviceId`), or add the column to the query's final `project`.
