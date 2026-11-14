# graylog_unknown_field

Graylog does not know a field the query names, on the streams it searches.

Severity: warning. Reported by `opentide deploy` on a `graylog` block (graylog-1.0) and `opentide validate query --live`. Graylog's `UNKNOWN_FIELD`: no index of the definition's streams maps the field, so the query matches nothing until messages carry it. Field names are case-sensitive.

## Example

```text
graylog_unknown_field: Unknown field: Query contains unknown field: command_line_lc (line 1, column 12)
```

## How to fix

Check the field's spelling and case, the streams the definition searches, and the pipeline that writes the field.
