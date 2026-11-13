# exabeam_threshold_function

A threshold's `function` is not an Exabeam function, or its `field` is missing or blank.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). `function` is `count`, `unique_count`, `value`, `max`, `min`, `sum` or `average`. Every function but `count` reads a field, so `field` is required; `count` without a field counts events.

## Example

```yaml
threshold:
  function: sum
  operator: more_than
  value: 1000000
  within: 1h
```

## How to fix

Set `field` to the field the function reads (`bytes_out`), or use another function.
