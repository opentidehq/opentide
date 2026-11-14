# graylog_double_backslash

A Graylog query holds four backslashes in a row.

Severity: warning. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. In a Graylog query, `\\` is one literal backslash, so `\\\\` matches two, which a Windows path does not have.

## Example

```yaml
configurations:
  graylog:
    query: 'image_lc:/.*\\\\\\\\mshta\.exe/'
```

## How to fix

Write one literal backslash as `\\` in the query text (in single-quoted YAML, as written).
