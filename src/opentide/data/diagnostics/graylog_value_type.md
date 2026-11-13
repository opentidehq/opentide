# graylog_value_type

A query compares a Graylog field with a value of the wrong type.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0) and `opentide validate query --live`. Graylog's `INVALID_VALUE_TYPE`: the field is mapped as a number or a date, and the value is not one.

## Example

```text
graylog_value_type: Invalid value type: Type of EventID is long, cannot use value abc (line 1, column 30)
```

## How to fix

Compare the field with a value of its type.
