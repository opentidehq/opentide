# datadog_window_order

`detection.window` is longer than `signal.keep_alive` or `signal.max_duration`.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). A signal would close before the window its cases are tested over ends. `keep_alive` defaults to `1h` and `max_duration` to `1d`, so a window of `2h` or more needs a longer `keep_alive`.

## Example

```yaml
configurations:
  datadog:
    detection:
      window: 1h
    signal:
      keep_alive: 30m
```

## How to fix

Make `signal.keep_alive` and `signal.max_duration` at least as long as `detection.window`, or shorten the window.
