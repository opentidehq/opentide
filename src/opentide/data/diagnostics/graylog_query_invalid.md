# graylog_query_invalid

Graylog refused a query, so deploy saved nothing.

Severity: error. Reported by `opentide deploy` on a `graylog` block (graylog-1.0). Before every create and update, deploy sends the query to `POST /api/search/validate`; Graylog stores a query it cannot parse without complaint, so an `ERROR` verdict fails the rule and no request saves it.

## Example

```text
graylog_query_invalid: Graylog refuses the query, so nothing is saved: Query parsing error:
Cannot parse query, cause: incomplete query, query ended unexpectedly (line 1, column 0)
```

## How to fix

Fix the query at the line and column Graylog names, and check it with `opentide validate query --platform graylog --live`.
