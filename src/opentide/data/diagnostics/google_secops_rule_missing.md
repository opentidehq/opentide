# google_secops_rule_missing

The Google SecOps rule a binding names no longer exists, and the rule is being retired.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Under `DISABLEMENT` or `DELETION`, reading or updating the recorded rule answered 404. Deploy created nothing and removed the binding.

## Example

```text
google_secops_rule_missing: the recorded rule no longer exists on the instance; its id is removed
```

## How to fix

Nothing to do: commit `.opentide/states/deployment/`.
