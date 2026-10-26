# object_type_unknown

A `sharing.toml` block lists an object type opentide cannot share.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
object_types = ["rule", "detection"]
```

## How to fix

List object families opentide shares: `threat`, `objective` and `rule`.
