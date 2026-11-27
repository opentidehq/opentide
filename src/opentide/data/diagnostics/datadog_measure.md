# datadog_measure

A query sets more than one measure, or `new_value` does not match the method.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). A query sets at most one of `count_distinct`, `sum`, `max` and `new_value`; with none it counts events. `new_value` lists one to five fields and goes with `method: new_value`, and every query of a `new_value` rule sets it. An `impossible_travel` query takes no measure: it measures the distance between logins itself.

## Example

```yaml
configurations:
  datadog:
    queries:
      - query: source:okta
        count_distinct: "@usr.email"
        sum: "@bytes"
```

## How to fix

Keep one measure per query, and set `new_value` only under `method: new_value`.
