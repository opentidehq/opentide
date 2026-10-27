# metadata_recommended

An object has no `metadata.author` or `metadata.organisation`.

Severity: note. Reported by `opentide lint` (metadata check).

## Example

```yaml
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  # author and organisation are missing
```

## How to fix

Add the missing keys under `metadata`. They are recommended, not required: lint fails only with `--strict`.
