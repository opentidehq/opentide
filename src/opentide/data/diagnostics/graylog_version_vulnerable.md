# graylog_version_vulnerable

A Graylog tenant runs a version affected by the access-token revocation flaw.

Severity: warning. Reported by `opentide deploy` on a `graylog` tenant (graylog-1.0), once per run. Graylog below 6.3.12, 7.0.16 or 7.1.12 is affected by GHSA-j769-9gv9-65gr: a revoked access token may keep working. Deploy goes on.

## Example

```text
graylog_version_vulnerable: Graylog 6.3.5 does not revoke access tokens reliably (GHSA-j769-9gv9-65gr)
```

## How to fix

Upgrade the server to 6.3.12, 7.0.16, 7.1.12 or later.
