# google_secops_rule_recreated

The Google SecOps rule a binding names no longer exists, so deploy created it again.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Reading or updating the recorded rule answered 404. Deploy verified and created the rule again and replaced the binding with the new id. Detections of the old rule are not carried over.

## Example

```text
google_secops_rule_recreated: the recorded rule no longer exists on the instance; creating it again
```

## How to fix

Nothing to do: commit `.opentide/states/deployment/` with the new id. Find out who deleted the rule if that was not intended.
