# graylog_regex_operator

A Graylog regex holds a character Lucene reads as a regex operator.

Severity: warning. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. An unescaped `#`, `&`, `<`, `>` or `~`, other than a numeric interval `<n-m>`, is an operator in Lucene's regex syntax, and Graylog's validator still says OK.

## Example

```yaml
configurations:
  graylog:
    query: url_lc:/.*#section.*/
```

## How to fix

Escape the character (`\#`) when you mean it literally.
