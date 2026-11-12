# graylog_analyzed_field

A regex, wildcard or range applies to Graylog's analysed message field.

Severity: warning. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. `message` and `full_message` are tokenised and lower-cased, so a regex or wildcard matches single tokens, never the whole value.

## Example

```yaml
configurations:
  graylog:
    query: message:/.*powershell -enc.*/
```

## How to fix

Match a keyword field the pipeline extracts, or search the words as a phrase (`message:"powershell -enc"`).
