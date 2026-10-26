# duplicate_id

Two object files carry the same UUID.

Severity: error. Reported by `opentide validate` (id-uniqueness check).

## Example

```text
objects/rules/a.yaml     metadata.uuid: 00000000-0000-4000-8003-000000000001
objects/rules/a-copy.yaml metadata.uuid: 00000000-0000-4000-8003-000000000001
```

## How to fix

Give the copy a fresh UUID v4. A copied file is the usual cause. Keep the UUID on the object that is already deployed or referenced, since references and deployment state follow the UUID.
