# api_key_literal

A `sharing.toml` block holds its API key as a literal.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
api_key = "8f4c…"
```

## How to fix

Reference an environment variable instead, `api_key = "${MISP_API_KEY}"`, and set it in your shell or CI secrets. opentide never prints the literal.
