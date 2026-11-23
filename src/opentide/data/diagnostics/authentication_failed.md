# authentication_failed

A tenant refused the check itself, not a query: its credentials, or the account's rights on it.

Exit 1, as `failure.code` of `validate query --live`. The run goes on: that tenant's remaining queries are not sent and the next tenant is checked; `refused_tenants` names every tenant that refused, and `rejected` lists every query any tenant refused as invalid. A query refused as invalid is `query_rejected`. Deploy failures, `doctor` and the SDKs use the same code for the same refusal.

## Example

```text
opentide validate query --live --platform splunk
```

## How to fix

Check the credentials of the tenant named in `tenant` (the environment variables its setup names) and the account's rights on the tenant.
