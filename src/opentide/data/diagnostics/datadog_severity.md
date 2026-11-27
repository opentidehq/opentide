# datadog_severity

A case severity is not one of Datadog's five statuses.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). A case's `severity` is `info`, `low`, `medium`, `high` or `critical`, in lower case. Left out, it comes from `response.alert_severity`, else `info`.

## Example

```yaml
configurations:
  datadog:
    cases:
      - condition: a > 5
        severity: urgent
```

## How to fix

Use one of the five values, or leave `severity` out.
