# microsoft_defender_column_type

A Microsoft Defender entity or action is mapped from a column that is not text.

Severity: warning. Reported by the analysis engine on a `microsoft_defender` block (microsoft-defender-1.0), with its query's findings: `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. An entity field (`hosts.device_id`, `ips.address`, `files.sha256`, ...) or an action's column holds an identifier, a name or an address, which Defender reads as text. The engine reports a mapping from an output column whose type it knows and is neither `string` nor `guid`: a `datetime`, a number, a `bool`, a `dynamic` bag. Custom details and alert placeholders show any type and are not checked. When the engine does not know the column's type, or cannot infer the query's output, nothing is reported. The finding is on the field.

## Example

```yaml
configurations:
  microsoft_defender:
    query: |
      DeviceNetworkEvents
      | extend Remote = parse_json(AdditionalFields)
      | project Timestamp, ReportId, DeviceId, Remote
    entities:
      ips:
        - address: Remote   # a dynamic column
```

## How to fix

Map a text column, or convert the value in the query: `| extend RemoteAddress = tostring(Remote.ip)`, then `address: RemoteAddress`.
