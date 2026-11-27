# datadog_duration

A duration is not one of the values its key accepts.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). `detection.window`, `signal.keep_alive` and `signal.max_duration` take `0`, `1m`, `5m`, `10m`, `15m`, `30m`, `1h`, `2h`, `3h`, `6h`, `12h` or `1d`. `detection.bucket` takes `5m`, `10m`, `15m`, `30m`, `1h` or `3h`. `detection.learning` takes `0d` to `30d` under `new_value`, `1h`, `6h`, `12h`, `1d`, `2d`, `7d` or `14d` under `anomaly`, and `1d` to `30d` under `impossible_travel`. `detection.forget_after` takes `1d` to `30d`. Datadog's API takes only these values.

## Example

```yaml
configurations:
  datadog:
    detection:
      window: 7m
```

## How to fix

Pick the nearest value the key takes: `5m` or `10m` here.
