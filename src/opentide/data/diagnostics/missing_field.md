# missing_field

A `sharing.toml` block is missing a required field.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
[[misp]]
name = "misp-prod"
# url, max_tlp and api_key are required
```

## How to fix

Add the field the message names to the block.
