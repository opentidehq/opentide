# bitdefender_create_no_id

A GravityZone create answered something other than a 24-hex rule id.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). Deploy sends `returnRuleId: true` and records the id it gets back. Without one the rule may exist on the tenant with no binding in `.opentide/states/deployment/`.

## Example

```text
bitdefender_create_no_id: createCustomRule for 'Encoded PowerShell' answered True
```

## How to fix

Find the rule by name in the GravityZone console and record its id in the rule's deployment state shard, or delete it and deploy again.
