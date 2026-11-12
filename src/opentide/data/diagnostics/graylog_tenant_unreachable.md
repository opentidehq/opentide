# graylog_tenant_unreachable

A Graylog tenant did not answer.

Severity: error. Reported by `opentide deploy` on a `graylog` tenant (graylog-1.0): DNS, a refused or reset connection, TLS or a timeout on a request other than a create. No further rule on the tenant deploys.

## Example

```text
graylog_tenant_unreachable: HTTPSConnectionPool(host='graylog.example.com', port=443): Max retries exceeded
```

## How to fix

Check the tenant's `url`, the network path, and `ssl`.
