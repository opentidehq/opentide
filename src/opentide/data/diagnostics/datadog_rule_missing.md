# datadog_rule_missing

The rule a deployment state names no longer exists on the Datadog tenant.

Severity: warning. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). Under a DELETION or a DISABLEMENT status, the stored id answered `404`, or `isDeleted: true`. There is nothing to delete or disable, so the id is removed from the deployment state.

## Example

```text
datadog_rule_missing: Datadog rule abc-def-ghi no longer exists on the tenant; its id is removed
```

## How to fix

Nothing to do; commit the updated `.opentide/states/deployment/` shard.
