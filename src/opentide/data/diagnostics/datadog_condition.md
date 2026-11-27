# datadog_condition

A case's condition does not parse, names an unknown query, or does not suit the method.

Severity: error. Reported by `opentide validate` on a `datadog` block (`platform::datadog::1.0`). A condition compares query names with numbers, joined by `&&` or `||`: `failed > 10 && success > 0`. The query name comes first (Datadog allows `a > 3`, not `3 < a`). `threshold` and `anomaly` cases need a condition. Under `anomaly` the number is a percentile between 0 and 1 (`a > 0.995`), and `<` and `<=` are documented for threshold rules only. Parentheses and `==` are not documented.

## Example

```yaml
configurations:
  datadog:
    queries:
      - name: failed
        query: source:okta @evt.outcome:FAILURE
    cases:
      - condition: 3 < failed
```

## How to fix

Put the query name first (`failed > 3`), name a query the block has, and under `anomaly` compare with a fraction.
