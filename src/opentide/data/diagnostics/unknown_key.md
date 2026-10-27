# unknown_key

`sharing.toml` has a key opentide does not read.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
[[misp]]
name = "misp-prod"
verify_tls = false     # the key is verify_ssl
```

## How to fix

Remove the key or correct its spelling. The only sharing integration is `[[misp]]`.
