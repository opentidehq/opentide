# exabeam_threshold_value

A threshold's `value` does not have the shape its operator takes.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). `more_than` and `less_than` compare with a number (`count` and `unique_count`: a non-negative integer); `in` and `not_in` with a non-empty list of strings or numbers. A list item holds no comma, because Exabeam joins the list with commas.

## Example

```yaml
threshold:
  function: count
  operator: more_than
  value: 2.5
  within: 10m
```

## How to fix

Write a whole number for `count` and `unique_count`, a number for the other numeric functions, and a list for `in` and `not_in`.
