# graylog_schedule

A Graylog block's schedule is invalid.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `schedule` or the offending `schedule.<key>`. Exactly one of `every` and `cron` is set (or neither); `every` and `window` are durations greater than zero (`5m`, `1h10m`, `PT15M`); `cron` is a Quartz expression of 6 or 7 fields with `?` in day of month or day of week; `timezone` is an IANA zone name; `window` is set when `cron` is.

## Example

```yaml
configurations:
  graylog:
    schedule: {cron: "0 */5 * * * ?"}
```

## How to fix

Fix the key the finding names: with `cron`, also set `window` (`schedule: {cron: "0 */5 * * * ?", window: 5m}`).
