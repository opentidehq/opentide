# datadog_signal_group_by

A `signal.group_by` field is in no query's `group_by`.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). Signals can only be grouped by a field the queries group their matches by. Which subset Datadog requires exactly is not documented; opentide asks that each field be in some query's `group_by`.

## Example

```yaml
configurations:
  datadog:
    queries:
      - query: source:okta
        group_by: ["@usr.email"]
    signal:
      group_by: ["@usr.id"]
```

## How to fix

Group the signals by a field the queries group by, or add the field to a query's `group_by`.
