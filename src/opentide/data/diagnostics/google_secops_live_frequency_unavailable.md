# google_secops_live_frequency_unavailable

A Google SecOps rule with two or more event variables asks for `run_frequency: LIVE`.

Severity: warning (an advisory). Reported by `opentide validate` and `opentide lint` on a `google_secops` block (google-secops-1.0). Google allows `LIVE` for single-event rules only: `verifyRuleText` does not list it for this rule, so deploy refuses it with `google_secops_run_frequency_not_allowed` before writing anything. Google also counts a single event variable with `match` and a count or outcome condition as multi-event; the advisory does not try to decide that, and deploy still refuses.

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

Write `run_frequency: LIVE_CUSTOMIZABLE`, or remove `run_frequency`: deploy then sends none, and Google gives the rule its default frequency.
