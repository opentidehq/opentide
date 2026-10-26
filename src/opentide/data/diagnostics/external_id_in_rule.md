# external_id_in_rule

A rule still carries a vendor rule id key, which belongs in deployment state.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
configurations:
  sentinel:
    rule_id: 3f2a…           # not a key of the platform block
```

## How to fix

Run `opentide deploy migrate-state` and commit the rule together with `.opentide/states/deployment/`. Vendor ids live in one shard per rule there.
