# sentinel_lookback

A Microsoft Sentinel block's `scheduling.lookback` is shorter than 5 minutes, longer than 14 days, or shorter than its frequency.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `sentinel` block (sentinel-1.0), on `scheduling.lookback`. Microsoft's [scheduled analytics rules docs](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) (read 2026-11-27) say: "The allowed range for both of these parameters is from 5 minutes to 14 days", and "The query interval must be shorter than or equal to the lookback period": a lookback shorter than the frequency would leave gaps between runs. Sentinel refuses such a rule at deploy. Durations are compared in seconds (`1h` equals `PT60M`). A near-real-time rule (`scheduling.nrt: true`) is not checked, because deploy sends no lookback for it. A value that is not a duration is reported by the `schema` check's `value_error` instead.

## Example

```yaml
configurations:
  sentinel:
    scheduling:
      frequency: 1h
      lookback: 30m
```

## How to fix

Make the lookback at least the frequency and at most 14 days (`frequency: 1h`, `lookback: 2h`).
