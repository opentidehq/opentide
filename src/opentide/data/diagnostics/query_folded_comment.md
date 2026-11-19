# query_folded_comment

A `//` comment in a query that YAML folds into one line comments out the lines after it.

Severity: warning. Reported by the analysis engine on a rule or hunt query written as a `>` block, or as a plain or quoted value on several lines: YAML joins those lines with spaces, so the query the platform runs is one line, and a `//` comment on one of them runs to its end. The lines after the comment are then part of it, and the filter you read is not the one deployed. `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it, since the query that deploys is valid. It applies to every query language with `//` comments, such as KQL, ES|QL and YARA-L; a comment followed only by blank or comment lines loses nothing and is not reported.

## Example

```yaml
configurations:
  sentinel:
    query: >-
      SecurityEvent
      // only failed handles
      | where EventID == 4656
```

The query that deploys is `SecurityEvent // only failed handles | where EventID == 4656`: every `SecurityEvent` matches.

## How to fix

Write the query as a literal block (`|` or `|-`), which keeps each line a line, so the comment ends where its line does:

```yaml
    query: |-
      SecurityEvent
      // only failed handles
      | where EventID == 4656
```

Or remove the comment, or put it inside a `/* */` block where the language has one.
