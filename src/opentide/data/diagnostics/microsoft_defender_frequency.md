# microsoft_defender_frequency

A Microsoft Defender block's `schedule.frequency` is not `NRT`, `<n>H` or `<n>D`.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `n` is a positive whole number without a leading zero. Deploy sends it as an ISO 8601 duration: `NRT` as `PT0S`, `1H` as `PT1H`, `1D` as `P1D`. Which frequencies a tenant accepts is Defender's to say at deploy; the portal offers `NRT`, `1H`, `3H`, `12H` and `24H`. The finding is on `schedule.frequency`.

## Example

```yaml
configurations:
  microsoft_defender:
    schedule:
      frequency: PT1H
```

## How to fix

Write the frequency as `NRT`, `1H`, `3H`, `12H`, `24H` (or another `<n>H` or `<n>D`).
