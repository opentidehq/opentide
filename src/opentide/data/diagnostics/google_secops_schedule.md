# google_secops_schedule

A Google SecOps block's `schedule` cannot be sent with its run frequency, or holds a duration that is not one.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). Schedule customizations apply to `LIVE_CUSTOMIZABLE` and `HOURLY_CUSTOMIZABLE` rules only, and `late_arriving_data_adjustment` is a positive duration with unit `s`, `m`, `h` or `d` (`30m`, `2h`). The finding is on `schedule`, or on `schedule.late_arriving_data_adjustment`.

## Example

```yaml
configurations:
  google_secops:
    run_frequency: LIVE
    schedule:
      late_arriving_data_adjustment: half an hour
```

## How to fix

Set `run_frequency` to `LIVE_CUSTOMIZABLE` or `HOURLY_CUSTOMIZABLE`, or remove `schedule`; write the adjustment as a duration such as `30m`.
