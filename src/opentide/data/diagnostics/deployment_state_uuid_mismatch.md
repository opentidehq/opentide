# deployment_state_uuid_mismatch

A deployment state shard's file name and contents name different rules.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```text
.opentide/states/deployment/00000000-0000-4000-8003-00000000000A.json   # not lowercase
```

## How to fix

Name each shard `<uuid>.json` with the rule's lowercase canonical UUID, keep one shard per rule, and make `object_uuid` inside it match the file name.
