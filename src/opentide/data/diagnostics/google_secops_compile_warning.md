# google_secops_compile_warning

Google SecOps's compiler accepts a rule with a warning in a live query check.

Severity: warning. Reported by `opentide validate query --platform google_secops --live`, and logged by `opentide deploy` (google-secops-1.0): `verifyRuleText` answered `success` with a `WARNING` diagnostic, placed on the section key and line it falls in. The rule still deploys.

## Example

```text
google_secops_compile_warning: configurations.google_secops.events line 2, column 5: reference lists are deprecated
```

## How to fix

Read Google's message and its documentation link; change the section when the warning applies.
