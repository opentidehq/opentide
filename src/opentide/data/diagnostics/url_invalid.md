# url_invalid

A `sharing.toml` block's `url` is not an http(s) URL.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
url = "misp.example.org"
```

## How to fix

Write the full URL, scheme included: `https://misp.example.org`.
