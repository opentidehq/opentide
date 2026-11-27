# datadog_request_failed

Datadog answered a rule's request with an error other than a refusal of the rule.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). Any answer that is not `400` (`datadog_rule_invalid`), a refused key, a stale version or a rate limit: a `404` on a path, a `5xx` on an update or a read after its retries. The rule fails; the next rule is tried.

## Example

```text
datadog_request_failed: PUT /api/v2/security_monitoring/rules/abc-def-ghi: HTTP 500: Internal Server Error
```

## How to fix

Deploy again; if it persists, check Datadog's status page.
