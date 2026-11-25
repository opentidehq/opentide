# microsoft_defender_grouping

A Microsoft Defender block's `alert.grouping` is not `alert_per_event` or `single_alert`.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `grouping` is beta-only and is sent as Graph's `eventGroupingKind` (`alertPerEvent`, `singleAlert`). The finding is on `alert.grouping`.

## Example

```yaml
configurations:
  microsoft_defender:
    alert:
      grouping: singleAlert
```

## How to fix

Write `single_alert` or `alert_per_event`, or remove the key: Defender then creates one alert per event.
