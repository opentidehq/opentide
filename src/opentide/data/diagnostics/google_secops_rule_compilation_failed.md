# google_secops_rule_compilation_failed

Google reports that a deployed Google SecOps rule no longer compiles.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0), from the rule it reads before an update. `compilationState` `FAILED` happens after a backwards-incompatible change to Google's compiler, or when a reference list or data table the rule uses is gone; the rule then does not run. Deploy goes on: a changed text is verified and sent as usual.

## Example

```text
google_secops_rule_compilation_failed: Google reports the rule's compilation as FAILED
```

## How to fix

Run `opentide validate query --platform google_secops --live` to see Google's diagnostics for the rule, fix the sections they name, and deploy again.
