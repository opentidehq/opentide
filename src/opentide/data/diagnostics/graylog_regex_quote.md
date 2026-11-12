# graylog_regex_quote

A Graylog regex holds an unescaped double quote.

Severity: warning. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. The regex then matches nothing.

## Example

```yaml
configurations:
  graylog:
    query: 'command_line_lc:/.*"c:.*/'
```

## How to fix

Escape the quote (`\"`), or match without it.
