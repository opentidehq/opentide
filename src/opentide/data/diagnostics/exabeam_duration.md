# exabeam_duration

A duration is not a whole number and a unit its field takes, or `delay` is outside 7 to 180 minutes.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). A duration is a positive whole number and one unit, no space: `m`, `h`, `d`, and `w` for `suppression.for` only. Compound (`1h30m`) and ISO 8601 durations are not durations. `delay` is 7 to 180 minutes (`7m` to `180m`, `1h` to `3h`).

## Example

```yaml
configurations:
  exabeam:
    delay: 5m
```

## How to fix

Write the duration in one unit (`90m`, not `1h30m`), and keep `delay` between `7m` and `3h`.
