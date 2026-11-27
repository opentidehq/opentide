# datadog_rate_limited

Datadog's rate limit held after the waits a deploy allows.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). A `429` is waited out for the seconds its `X-RateLimit-Reset` gives and sent again, at most three times. A reset more than 120 seconds away is not waited for. The rule fails; the next rule is tried.

## Example

```text
datadog_rate_limited: POST /api/v2/security_monitoring/rules: Datadog's rate limit resets in 600s, more than the 120s a deploy waits
```

## How to fix

Deploy again later, or deploy fewer rules in one run.
