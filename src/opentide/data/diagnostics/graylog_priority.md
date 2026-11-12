# graylog_priority

A Graylog block's priority is not one of Graylog's priorities.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `priority`. The priorities are `Informational`, `Low`, `Medium`, `High` and `Critical`.

## Example

```yaml
configurations:
  graylog:
    priority: Urgent
```

## How to fix

Write one of the five, or leave `priority` out to derive it from `response.alert_severity`.
