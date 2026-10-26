# schemas_fresh

Every JSON schema this opentide version generates exists.

Reported by `opentide doctor`. Warns when one is missing. Schemas carry no version stamp, so only presence is checked.

## Example

```text
! 1 schema(s) this version generates are missing: rule · schemas_fresh
  → opentide generate schemas
```

## How to fix

Run `opentide generate schemas`.
