# graylog_leading_wildcard

A Graylog query term starts with `*` or `?`.

Severity: error. Reported by the analysis engine on a Graylog query (graylog-1.0, Query diagnostics): the `query` of a `graylog` block and `.lucene` files under `--platform graylog`, in `opentide validate`, `opentide validate query`, `opentide lint`, the editor and `opentide tui`. Graylog passes the query to `query_string` with `allow_leading_wildcard` from the server's `allow_leading_wildcard_searches`, `false` by default, and refuses the query ("'*' or '?' not allowed as first character"). opentide drops the finding when every tenant the block deploys to sets `allow_leading_wildcard = true`; offline, with no tenant, it is an error.

## Example

```yaml
configurations:
  graylog:
    query: image_lc:*\\mshta.exe
```

## How to fix

Write a regex with a leading `.*` (`image_lc:/.*\\mshta\.exe/`), or set `allow_leading_wildcard = true` on every tenant whose server allows leading wildcards.
