# google_secops_verify_failed

Google SecOps does not compile a rule, so deploy neither creates nor updates it.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Deploy sends the assembled rule to `verifyRuleText` before every create and every text update. Each of Google's diagnostics is reported at the section key and line it falls in (`configurations.google_secops.events line 3, column 5`), or on the block when it falls in the generated header or meta.

## Example

```text
google_secops_verify_failed: Google SecOps does not compile rule password_spray: configurations.google_secops.events line 3, column 5: field principal.nope does not exist
```

## How to fix

Fix the section the diagnostic names and run `opentide validate query --platform google_secops --live`, which asks the same compiler without deploying.
