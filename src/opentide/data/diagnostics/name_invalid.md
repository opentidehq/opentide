# name_invalid

A `sharing.toml` block name is not 1-64 lowercase letters, digits, `-` or `_`.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
[[misp]]
name = "MISP Prod"
```

## How to fix

Rename the block, for example `misp-prod`.
