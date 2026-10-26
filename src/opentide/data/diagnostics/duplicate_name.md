# duplicate_name

Two `sharing.toml` blocks share a name.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
[[misp]]
name = "misp-prod"

[[misp]]
name = "misp-prod"
```

## How to fix

Give each block a unique `name`; `share --target` selects blocks by it.
