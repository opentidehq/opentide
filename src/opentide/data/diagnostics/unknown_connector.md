# unknown_connector

`sharing.toml` has a top-level array that names a sharing connector opentide does not have; it was skipped.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`. The exported `sharing.toml` schema accepts the array, so an editor does not flag it as an error.

## Example

```toml
[[opencti]]
name = "cti"
```

## How to fix

Remove the block. The only sharing connector is `[[misp]]`.
