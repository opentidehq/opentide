# graylog_regex_unsupported

A Graylog regex uses syntax Lucene's regex engine does not have.

Severity: error. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. An inline flag such as `(?i)`, `\b`, `\B`, lookahead or lookbehind, or a backreference: Lucene's regex engine accepts none of them, and Graylog matches nothing without saying so.

## Example

```yaml
configurations:
  graylog:
    query: command_line:/(?i).*mimikatz.*/
```

## How to fix

Match a lower-cased copy of the field instead (`command_line_lc:/.*mimikatz.*/`), written by a tenant pipeline; see the case section of the Graylog platform spec.
