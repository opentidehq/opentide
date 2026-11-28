# datadog_method_unsupported

`detection.method` is not a detection method of `platform::datadog::1.0`.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). 1.0 takes `threshold`, `new_value`, `anomaly` and `impossible_travel`, written in lower case. Datadog no longer accepts new `signal_correlation` rules, and sequence rules, which correlate other rules' signals, wait for 1.x.

## Example

```yaml
configurations:
  datadog:
    detection:
      method: sequence
```

## How to fix

Use one of the four methods. To count another rule's signals, write a query `from: signals`.
