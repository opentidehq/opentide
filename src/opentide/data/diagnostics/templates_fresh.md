# templates_fresh

Every template this opentide version generates exists and matches what it would write.

Reported by `opentide doctor`. Warns when a template is missing or differs, usually after an upgrade.

## Example

```text
! 2 template(s) differ from what this version generates: rule, threat · templates_fresh
  → opentide generate templates
```

## How to fix

Run `opentide generate templates`.
