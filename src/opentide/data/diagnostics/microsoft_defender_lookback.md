# microsoft_defender_lookback

A Microsoft Defender block's `schedule.lookback` is not a duration, is set on a near-real-time rule, or is shorter than its frequency.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `lookback` is beta-only and is `<n>H` or `<n>D`. Graph requires it to be at least `frequency` and does not take it with `frequency: NRT` (`1D` counts as `24H`). The finding is on `schedule.lookback`.

## Example

```yaml
configurations:
  microsoft_defender:
    schedule:
      frequency: NRT
      lookback: 1H
```

## How to fix

Remove `lookback` from a near-real-time rule, or make it at least the frequency (`frequency: 1H`, `lookback: 4H`).
