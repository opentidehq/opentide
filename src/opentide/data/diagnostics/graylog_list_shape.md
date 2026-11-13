# graylog_list_shape

A Graylog list field is not a string or a list of distinct, non-blank strings.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at the list field: `tags`, `streams`, `stream_categories`, `event_key`, `notifications` or `aggregation.group_by`. Each takes one string or a list of strings; a string is a one-item list.

## Example

```yaml
configurations:
  graylog:
    streams: [sysmon, sysmon]
```

## How to fix

Write one string, or a list whose items are non-blank and not repeated.
