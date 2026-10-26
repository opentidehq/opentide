# organisation_uuid_mismatch

The organisation configured for a sharing target is not the one its API key belongs to.

Exit 1, as `failure.code` and `preflight`. Nothing was sent.

## Example

```text
opentide share push --target misp-prod
```

## How to fix

Set the target's organisation UUID in `sharing.toml` to the one the API key belongs to, or use that organisation's key.
