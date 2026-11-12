# graylog_overlapping_window

A Graylog filter searches a window longer than its interval.

Severity: warning. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `schedule`; never fails a rule. With `window` longer than `every`, consecutive runs search overlapping time ranges, and a filter (no `aggregation`) creates an event for each message once per run that sees it.

## Example

```yaml
configurations:
  graylog:
    schedule: {every: 5m, window: 15m}
```

## How to fix

Make `window` equal to `every` (the default), or turn the filter into an aggregation.
