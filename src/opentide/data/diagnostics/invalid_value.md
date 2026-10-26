# invalid_value

A `sharing.toml` value has the wrong type.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
enabled = "yes"           # must be a boolean
```

## How to fix

Use the type the message names: `true`/`false` for flags, a list of strings for lists.
