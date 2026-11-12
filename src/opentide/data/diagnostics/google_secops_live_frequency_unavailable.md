# google_secops_live_frequency_unavailable

A Google SecOps rule with two or more event variables asks for `run_frequency: LIVE`.

Severity: warning (an advisory). Reported by `opentide validate` and `opentide lint` on a `google_secops` block (google-secops-1.0). Google runs multi-event rules at `LIVE_CUSTOMIZABLE` at best and stores that instead, so the deployed rule differs from the block on every deploy.

## Example

```yaml
configurations:
  google_secops:
    run_frequency: LIVE
    events: |
      $fail.metadata.event_type = "USER_LOGIN"
      $success.metadata.event_type = "USER_LOGIN"
```

## How to fix

Write `run_frequency: LIVE_CUSTOMIZABLE`, or remove `run_frequency` to take the first frequency Google allows.
