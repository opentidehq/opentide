# exabeam_rule_missing

A rule to disable was already gone from Exabeam, so its id was removed.

Severity: warning. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). Under `DISABLEMENT`, the `PUT` answered `404`. Deploy creates nothing and removes the binding from `.opentide/states/deployment/`.

## Example

```text
exabeam_rule_missing: the recorded rule no longer exists on the tenant; its id is removed
```

## How to fix

Commit the updated deployment state. Nothing else is needed: the rule is not on the tenant.
