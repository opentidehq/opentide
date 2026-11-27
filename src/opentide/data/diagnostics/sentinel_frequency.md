# sentinel_frequency

A Microsoft Sentinel block's `scheduling.frequency` is shorter than 5 minutes or longer than 14 days.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `sentinel` block (sentinel-1.0), on `scheduling.frequency`. Microsoft's [scheduled analytics rules docs](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) (read 2026-11-27) say of the query interval and the lookback period: "The allowed range for both of these parameters is from 5 minutes to 14 days." Sentinel refuses a rule outside that range at deploy. A near-real-time rule (`scheduling.nrt: true`) is not checked, because deploy sends no frequency for it. A value that is not a duration is reported by the `schema` check's `value_error` instead.

## Example

```yaml
configurations:
  sentinel:
    scheduling:
      frequency: 1m
      lookback: 1h
```

## How to fix

Run the rule every 5 minutes or more, at most every 14 days (`frequency: 5m`, `PT1H`, `P1D`). For a rule that must fire as events arrive, set `scheduling.nrt: true` instead.
