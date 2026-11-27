# kql_rule_search_star

A Microsoft Sentinel analytics rule's query contains `search *`, which Microsoft does not allow in a scheduled rule.

Severity: error. Reported by the analysis engine on the query of a `sentinel` block (the KQL rule profile), at the `search` keyword: `opentide validate` (its `queries` check) and an editor running `opentide lsp start` show it. Microsoft's [scheduled analytics rules docs](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) (read 2026-11-27) say: "The query length should be between 1 and 10,000 characters and can't contain "`search *`" or "`union *`"." It is `search` with no `in (...)` list and a bare `*`. A hunt's search (`response.procedure.searches`) may use it: there, an unscoped `search` is the performance warning `kql_unscoped_search`, which this error replaces in a rule. A Microsoft Defender block is not checked: Defender's custom detection docs set no such limit.

## Example

```yaml
configurations:
  sentinel:
    query: |
      search * | where Account == "admin"
```

## How to fix

Start from the tables the rule needs (`SecurityEvent | where Account == "admin"`), or scope the search: `search in (SecurityEvent, SigninLogs) "admin"`.
