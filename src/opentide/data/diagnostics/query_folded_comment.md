# query_folded_comment

A `//` comment in a query that YAML folds into one line comments out the lines after it.

Severity: error. Reported by the analysis engine on a rule or hunt query written as a `>` block, or as a plain or quoted value on several lines: YAML joins those lines with spaces, so the query the platform runs is one line, and a `//` comment on one of them runs to its end. The lines after the comment are then part of it: the filter you read is not the one deployed, and the rule can match every event. `opentide validate` (its `queries` check) and `opentide validate query` fail on it, and an editor running `opentide lsp start` shows it. It applies to the query languages opentide checks offline whose comments are `//`: KQL (Sentinel, Defender), ES|QL and EQL (Elastic), CQL (CrowdStrike), YARA and YARA-L (Google SecOps). SentinelOne's PowerQuery has no offline engine, so its queries are not checked. A comment followed only by blank or comment lines loses nothing and is not reported, nor is a line that is more indented than the comment, which YAML keeps on a line of its own.

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

Or remove the comment.
