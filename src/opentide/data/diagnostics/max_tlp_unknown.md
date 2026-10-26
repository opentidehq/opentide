# max_tlp_unknown

A `sharing.toml` block's `max_tlp` is not a TLP value.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
max_tlp = "white"
```

## How to fix

Use a value of the TLP vocabulary: `clear`, `green`, `amber`, `amber+strict` or `red`.
