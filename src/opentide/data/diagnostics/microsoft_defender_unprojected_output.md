# microsoft_defender_unprojected_output

A Microsoft Defender query returns columns nothing in its block uses.

Severity: warning. Reported by the analysis engine on a `microsoft_defender` block's `query` (microsoft-defender-1.0), at its last operator: `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It applies when the query's output has a column that no entity, action, custom detail or alert `{{placeholder}}` names and a custom detection does not require, typically because the query ends without a `project` and returns every column of its table. Defender derives entity mappings of its own from a rule's result columns (IP addresses, files, processes, URLs, registry values), beyond the ones the block declares. They are stored on the rule, opentide never sees them, and Graph can later refuse them when the rule is enabled: a rule could be disabled and then not enabled again until its `entityMappings` were rewritten by hand. Projecting only the columns the rule uses prevents it. When the engine cannot infer the output, nothing is reported.

## Example

```yaml
configurations:
  microsoft_defender:
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe"
    entities:
      accounts:
        - upn: AccountUpn
```

## How to fix

End the query with a `project` of the columns a custom detection needs and the ones the block names. The finding suggests it, and an editor offers to append it: `| project Timestamp, DeviceId, ReportId, AccountUpn`.
