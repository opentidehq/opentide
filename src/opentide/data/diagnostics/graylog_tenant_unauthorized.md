# graylog_tenant_unauthorized

A Graylog tenant refused the access token.

Severity: error. Reported by `opentide deploy` on a `graylog` tenant (graylog-1.0). Graylog answered 401; no rule on the tenant deploys. The token is sent as HTTP Basic, the token as user name and `token` as password.

## Example

```text
graylog_tenant_unauthorized: tenant graylog-prod refused the access token: HTTP 401
```

## How to fix

Set the token's environment variable (`token = "$GRAYLOG_TOKEN"`) to a valid access token; access tokens expire after 30 days by default.
