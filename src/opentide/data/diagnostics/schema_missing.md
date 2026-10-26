# schema_missing

An object has no `metadata.schema`, so no schema can check it.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  # schema: rule::1.0 is missing
```

## How to fix

Add `metadata.schema` with the identifier of the revision the object follows, for example `rule::1.0`, `threat::1.0` or `objective::1.0`. opentide does not fall back to the newest revision.
