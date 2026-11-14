# yaral_option

A YARA-L `options` key is unknown, or its value is of the wrong kind.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `configurations.google_secops` block (yara-l-1.0). `options` takes `allow_zero_values` (`true` or `false`) and `suppression_window` (a duration in `m`, `h` or `d`). The finding is on `options.<key>`.

## Example

```yaml
configurations:
  google_secops:
    options:
      suppression_window: 1 hour
```

## How to fix

Write `suppression_window: 1h`, and `allow_zero_values: true` without quotes.
