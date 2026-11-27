# kql_rule_too_long

A Microsoft Sentinel analytics rule's query is longer than the 10,000 characters Microsoft allows.

Severity: error. Reported by the analysis engine on the query of a `sentinel` block (the KQL rule profile), on its first line: `opentide validate` (its `queries` check) and an editor running `opentide lsp start` show it. Microsoft's [scheduled analytics rules docs](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) (read 2026-11-27) say: "The query length should be between 1 and 10,000 characters", and suggest user-defined functions to stay under it. The query is counted in characters, not bytes, without the blank lines and spaces around it. The `exclusions` deploy appends for a tenant are not counted, so a query just under the limit passes this check and can still be refused once deploy adds them. A hunt's search is not checked, nor a Microsoft Defender block: Defender's custom detection docs set no such limit.

## Example

A `sentinel` block whose `query` holds 10,001 characters or more.

## How to fix

Move parts of the query into a saved workspace function and call it from the rule ("a single function can replace dozens of lines of code"), or split the rule in two.
