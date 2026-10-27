# api_key_unset

An enabled sharing target has no API key.

Exit 1, as `failure.code` and `preflight`. Nothing was sent.

## Example

```text
opentide share push --target misp-prod
```

## How to fix

Set the environment variable the target's `api_key` names in `sharing.toml`.
