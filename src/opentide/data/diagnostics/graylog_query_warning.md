# graylog_query_warning

Graylog has a reservation about a query.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0) and `opentide validate query --live`: a `WARNING` or `INFO` explanation of `POST /api/search/validate` that is neither an unknown field nor a value type, such as `INVALID_OPERATOR`.

## Example

```text
graylog_query_warning: Invalid operator: Query contains invalid operator "and" (line 1, column 10)
```

## How to fix

Read Graylog's explanation and change the query; an operator is upper case (`AND`).
