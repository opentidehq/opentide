# graylog_query_blank

A Graylog block has no query, or an empty one.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `query`. Every event definition searches with a query; an empty one would search every message.

## Example

```yaml
configurations:
  graylog:
    status: STAGING
    query: ""
```

## How to fix

Write the Graylog search query, for example `query: EventID:1 AND image_lc:/.*mshta\.exe/`.
