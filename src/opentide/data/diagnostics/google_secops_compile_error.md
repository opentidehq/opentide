# google_secops_compile_error

Google SecOps's compiler refuses a rule in a live query check.

Severity: error. Reported by `opentide validate query --platform google_secops --live` (google-secops-1.0). The rule's assembled text is compiled by `verifyRuleText`, which resolves the instance's reference lists and data tables and creates nothing. Each `ERROR` diagnostic is placed on the section key and line it falls in, with Google's message and documentation link.

## Example

```text
google_secops_compile_error: configurations.google_secops.condition line 1, column 1: event variable $success is not used
```

## How to fix

Fix the section and line the finding names, then run the check again.
