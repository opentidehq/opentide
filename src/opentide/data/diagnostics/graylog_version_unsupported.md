# graylog_version_unsupported

A Graylog tenant runs a version opentide does not deploy to.

Severity: error. Reported by `opentide deploy` on a `graylog` tenant (graylog-1.0). Deploy reads `GET /api/system` once per tenant, before any write, and builds every request for that version. Graylog below 6.3, or a server that reports no version, stops the tenant.

## Example

```text
graylog_version_unsupported: tenant graylog-prod runs Graylog '6.2.4+1a2b3c4'; opentide deploys to Graylog 6.3 and later
```

## How to fix

Upgrade the server to Graylog 6.3 or later, or remove the tenant from `platforms/graylog.toml`.
