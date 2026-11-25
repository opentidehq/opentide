# microsoft_defender_severity

A Microsoft Defender block's `alert.severity` is not one of opentide's five severities.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `alert.severity` is `Informational`, `Low`, `Medium`, `High` or `Critical`, exact case. Deploy sends it lower-cased, and `Critical` as `high`, Graph's highest. The finding is on `alert.severity`.

## Example

```yaml
configurations:
  microsoft_defender:
    alert:
      severity: high
```

## How to fix

Write the severity with its capital (`High`), or remove it: deploy then uses `response.alert_severity`, else `Medium`.
