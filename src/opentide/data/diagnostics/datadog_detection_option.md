# datadog_detection_option

A `detection` key the method does not take, or `new_value` without `forget_after`.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). `learning` goes with `new_value`, `anomaly` and `impossible_travel`; `forget_after` with `new_value`, where it is required; `bucket` and `tolerance` (a whole number, 1 to 5) with `anomaly`; `detect_ip_transitions` with `impossible_travel`. `threshold` takes only `method` and `window`.

## Example

```yaml
configurations:
  datadog:
    detection:
      method: threshold
      bucket: 5m
```

## How to fix

Remove the key, or use the method it belongs to. A `new_value` rule needs `forget_after`.
