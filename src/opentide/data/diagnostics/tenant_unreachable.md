# tenant_unreachable

A tenant did not answer, so nothing was checked on it.

Exit 1, as `failure.code`, from `validate query --live` (after three queries in a row get no answer, or when the tenant answers none) and from the deploy commands. `tenant` and `host` name it, `advice` says what to check.

## Example

```text
opentide validate query --live --platform splunk
```

## How to fix

Check the tenant's URL in `.opentide/configurations/platforms/<platform>.toml` and the network path to its host; behind a proxy, pass `opentide --proxy`. If the tenant is up and only slow, raise `--check-timeout` or `OPENTIDE_QUERY_CHECK_TIMEOUT`.
