# datadog_tenant_unauthorized

Datadog refused the tenant's API or application key.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). Also reported by `validate query --live` and `opentide query`. Datadog answered `403`, or `401` on a request that is not an update. The application key needs `security_monitoring_rules_read` and `security_monitoring_rules_write` (validation needs write), and `logs_read_data` for queries. The tenant's other rules are not attempted.

## Example

```text
datadog_tenant_unauthorized: tenant datadog-eu refused GET /api/v2/security_monitoring/rules/abc-def-ghi: HTTP 403 (Forbidden)
```

## How to fix

Check `$DD_API_KEY` and `$DD_APP_KEY`, the scopes of the application key, and that the tenant's `site` is the organisation's.
