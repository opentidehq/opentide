# organisation_uuid_invalid

A `sharing.toml` block's `organisation_uuid` is not a UUID.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
organisation_uuid = "acme"
```

## How to fix

Use the UUID of the MISP organisation, as MISP shows it.
