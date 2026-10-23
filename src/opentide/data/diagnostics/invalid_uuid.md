# invalid_uuid

An object's `metadata.uuid` is not a UUID v4.

Severity: error. Reported by `opentide validate` (uuid-format check).

## Example

```yaml
metadata:
  uuid: 1234-abcd
```

## How to fix

Replace it with a UUID v4. If other objects already point at the old value, update those references in the same change.
