# microsoft_defender_incident

A Microsoft Defender block's `incident` is not `{exclude_from_correlation: true|false}`.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `incident` is beta-only and is sent as Graph's `incidentConfiguration`. The finding is on `incident`.

## Example

```yaml
configurations:
  microsoft_defender:
    incident:
      exclude_from_correlation: yes please
```

## How to fix

Write `exclude_from_correlation: true` (each alert opens its own incident) or `false`.
