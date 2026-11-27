# datadog_tenant_unreachable

The Datadog tenant did not answer.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). DNS, TLS or a timeout stopped the request. The tenant's other rules are not attempted.

## Example

```text
datadog_tenant_unreachable: Cannot reach datadog tenant 'datadog-eu' at https://api.datadoghq.eu: dns error
```

## How to fix

Check the tenant's `site` or `api_url`, the network and the proxy, then deploy again.
