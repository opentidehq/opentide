# exabeam_threshold_operator

A threshold's `operator` is not one its function takes.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). `value` takes `in` or `not_in`; every other function takes `more_than` or `less_than`. Exabeam's `between` and `changed` are not supported in this revision: no published rule shows how their value is written.

## Example

```yaml
threshold:
  function: count
  operator: in
  value: [5, 10]
  within: 10m
```

## How to fix

Use `more_than` or `less_than` with a number, or the `value` function with `in` or `not_in`.
