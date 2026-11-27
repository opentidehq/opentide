# datadog_rule_invalid

Datadog refused the rule: its validation, or a write, answered `400`.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). Also reported by `validate query --live` on a block. Every create and update is first sent to `POST /security_monitoring/rules/validation`, so an invalid rule is reported before anything changes. The finding lists Datadog's `errors[]`.

## Example

```text
datadog_rule_invalid: POST /api/v2/security_monitoring/rules/validation: HTTP 400: Invalid query: unbalanced parenthesis
```

## How to fix

Fix what Datadog names, then run `opentide validate query --live --platform datadog` before deploying.
