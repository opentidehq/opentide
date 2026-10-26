# deprecated_field

An object uses a field its schema marks as deprecated.

Severity: warning. Reported by `opentide validate` (schema check); fails `--strict`.

## Example

```yaml
metadata:
  old_field: value       # deprecated: use new_field
```

## How to fix

Move the value to the field the message names, then remove the deprecated one.
