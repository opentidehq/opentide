# graylog_open_range

A Graylog range has an open end, which Graylog's validator refuses.

Severity: error. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. `[1 TO *]` and `{* TO 5}` are refused by `POST /api/search/validate`, so deploy would never save the definition.

## Example

```yaml
configurations:
  graylog:
    query: EventID:[4624 TO *]
```

## How to fix

Write the bound as a comparison (`EventID:>=4624`), or give both ends.
