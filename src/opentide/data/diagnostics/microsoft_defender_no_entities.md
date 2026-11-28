# microsoft_defender_no_entities

A Microsoft Defender block maps no entity.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `microsoft_defender` block (microsoft-defender-1.0) whose `entities` is unset, empty, or holds only empty kinds. The alert then names no device, user or mailbox, so it cannot be triaged or acted on by entity. It is an advisory: the rule validates and deploys.

## Example

```yaml
configurations:
  microsoft_defender:
    query: DeviceProcessEvents | where FileName =~ "powershell.exe"
    schedule:
      frequency: 1H
```

## How to fix

Map the columns the query returns: `entities: {hosts: [{device_id: DeviceId}]}`.
