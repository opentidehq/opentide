# missing_uuid

An object file has no UUID, so it cannot be indexed.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
name: Sentinel KQL Rule
metadata:
  schema: rule::1.0
  # uuid: is missing
```

## How to fix

Add `metadata.uuid` with a fresh UUID v4 (`opentide new rule` writes one, or run `uuidgen`). Never reuse the UUID of another object: references and deployment state follow it.
