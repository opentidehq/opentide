# datadog_condition_mixed

A condition mixes `&&` and `||`, whose precedence Datadog does not document.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `datadog` block (`platform::datadog::1.0`). Datadog documents both operators but not which binds tighter, so `a > 1 || b > 1 && c > 1` may not mean what it reads as. It is an advisory: the rule validates and deploys.

## Example

```yaml
configurations:
  datadog:
    cases:
      - condition: a > 1 || b > 1 && c > 1
```

## How to fix

Split the condition into two cases, which Datadog tests in order, or keep to one operator.
