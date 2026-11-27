# datadog_rule_recreated

The rule a deployment state names was gone, and deploy created it again.

Severity: warning. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). The stored id answered `404`, or `isDeleted: true`, so deploy created the rule anew and recorded its new id. A CI run that cannot persist deployment state does not create it (`deployment_state_unpersisted`).

## Example

```text
datadog_rule_recreated: Datadog rule abc-def-ghi no longer exists on the tenant; creating it again
```

## How to fix

Commit the updated `.opentide/states/deployment/` shard. If the rule was deleted on purpose, set the block's status to a DELETION status instead.
