# config_enum_unknown

A value is not one of those your deployment configuration declares.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
response:
  responders: Night Shift   # not declared under [[responders]]
```

## How to fix

Use one of the values the `expected` note lists, or declare the value in the matching `[[...]]` block (such as `[[responders]]`) of `deployment.toml` under `.opentide/configurations/`.
