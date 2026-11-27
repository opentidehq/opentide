# kql_rule_union_star

A Microsoft Sentinel analytics rule's query contains `union *`, which Microsoft does not allow in a scheduled rule.

Severity: error. Reported by the analysis engine on the query of a `sentinel` block (the KQL rule profile), at the `*`: `opentide validate` (its `queries` check) and an editor running `opentide lsp start` show it. Microsoft's [scheduled analytics rules docs](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) (read 2026-11-27) say: "The query length should be between 1 and 10,000 characters and can't contain "`search *`" or "`union *`"." It is a bare `*` among a `union`'s tables; a pattern such as `Sec*` names only the tables it matches and is not reported. A hunt's search (`response.procedure.searches`) may use it: there it is the performance warning `kql_unscoped_union`, which this error replaces in a rule. A Microsoft Defender block is not checked: Defender's custom detection docs set no such limit.

## Example

```yaml
configurations:
  sentinel:
    query: |
      union * | where EventID == 4625
```

## How to fix

Name the tables the rule reads: `union SecurityEvent, WindowsEvent | where EventID == 4625`.
