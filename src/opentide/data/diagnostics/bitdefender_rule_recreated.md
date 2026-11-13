# bitdefender_rule_recreated

The recorded GravityZone rule was gone, so deploy created it again.

Severity: warning. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). `updateCustomRule` answered `-32002` (resource not found): someone deleted the rule in the console. Deploy creates it again and replaces the id in `.opentide/states/deployment/`.

## Example

```text
bitdefender_rule_recreated: the recorded rule no longer exists on the tenant; creating it again
```

## How to fix

Commit the updated deployment state. Delete rules through a `DELETION` status, not in the console.
