# authentication_failed

A tenant refused the check itself, not a query: its credentials, or the account's rights on it.

Exit 1, as `failure.code` of `validate query --live`. No query is checked on that tenant, and the next tenant is checked; `refused_tenants` names every tenant that refused. Queries the tenant refused as invalid before that are still listed in `rejected`. A query refused as invalid is `query_rejected`.

## Example

```text
opentide validate query --live --platform splunk
```

## How to fix

Check the credentials of the tenant named in `tenant` (the environment variables its setup names) and the account's rights on the tenant.
