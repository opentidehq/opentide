# yaral_match_window

A YARA-L `match` window is not a duration in `m`, `h` or `d`, or is longer than its kind allows.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). A hop or sliding window in a rule is 1 minute to 14 days; a tumbling window (`type: tumbling`) at most 72 hours. Seconds are not a window unit.

## Example

```yaml
configurations:
  google_secops:
    match:
      group_by: [$user]
      window: 15d
```

## How to fix

Write a window within the bounds, such as `30m`, `12h` or `14d`.
