# bitdefender_criterion_relation

A criterion uses a relation its field does not take.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). Enum fields (`File.Operation`, `Registry.Operation`, `Registry.DataType`, `Connection.Protocol`, ...) take `is` or `any` only, and `*.MD5` and `*.SHA2` do not take `contains`.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: registry
      criteria:
        - field: Registry.Operation
          contains: key_*
```

## How to fix

Use `is` with one value or `any` with several: `any: [key_created, key_renamed]`.
