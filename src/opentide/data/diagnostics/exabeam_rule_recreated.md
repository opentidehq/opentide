# exabeam_rule_recreated

The recorded Exabeam rule was gone, so deploy created it again.

Severity: warning. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The `PUT` answered `404`: someone deleted the rule in the console. Deploy creates it again (after the name check) and replaces the id in `.opentide/states/deployment/`.

## Example

```text
exabeam_rule_recreated: the recorded rule no longer exists on the tenant; creating it again
```

## How to fix

Commit the updated deployment state. Delete rules through a `DELETION` status, not in the console.
