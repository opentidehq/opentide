# tenant_unreachable

A tenant did not answer, so nothing was checked on it.

Exit 1, as `failure.code` of `validate query --live`, after three queries in a row get no answer or when the tenant answers none. `tenant` and `host` name it, `advice` says what to check, and `rejected` lists the queries refused as invalid before it. Deploy failures, `doctor` and the SDKs use the same code for the same failure.

## Example

```text
opentide validate query --live --platform splunk
```

## How to fix

Check the tenant's URL in `.opentide/configurations/platforms/<platform>.toml` and the network path to its host; behind a proxy, pass `opentide --proxy`. If the tenant is up and only slow, raise `--check-timeout` or `OPENTIDE_QUERY_CHECK_TIMEOUT`.
