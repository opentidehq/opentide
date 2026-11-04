# templates_fresh

Every template this opentide version generates exists and matches what it would write.

Reported by `opentide doctor`. Warns when a template is missing or differs, usually after an upgrade. The comparison renders the `metadata` keys `lint.toml` requires (`[metadata].required`) as live keys, as `opentide generate templates` does. It also warns, naming the key, when `lint.toml` parses but holds a value opentide rejects: the templates cannot be compared until it is fixed.

## Example

```text
! 2 template(s) differ from what this version generates: rule, threat · templates_fresh
  → opentide generate templates
```

## How to fix

Run `opentide generate templates`. When the warning names a `lint.toml` key, fix that key first: `generate` fails on the same file, so regenerating does not clear it. A `lint.toml` that is not valid TOML is reported by the `configuration` check instead, and this check is skipped.
