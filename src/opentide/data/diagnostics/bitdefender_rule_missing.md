# bitdefender_rule_missing

A rule to disable is gone from GravityZone, so its recorded id was removed.

Severity: warning. Reported by `opentide deploy` under `DISABLEMENT` on a `bitdefender` block (bitdefender-1.0). `updateCustomRule` answered `-32002`. Nothing exists to disable, so deploy creates nothing and forgets the binding.

## Example

```text
bitdefender_rule_missing: the recorded rule no longer exists on the tenant; its id is removed
```

## How to fix

Commit the updated deployment state.
