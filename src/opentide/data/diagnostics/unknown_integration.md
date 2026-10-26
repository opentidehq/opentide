# unknown_integration

`sharing.toml` names a sharing integration opentide does not have; it was skipped.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
[[opencti]]
name = "cti"
```

## How to fix

Remove the block. The only sharing integration is `[[misp]]`.
