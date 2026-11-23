# kql_join_summarize_before_project

A `join` runs on the pipeline's own side while it still carries every column, and a `project` later in the same pipeline would have narrowed it.

Severity: warning, a cost hint and never an error. Reported by the analysis engine on a KQL query: `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. The query is legal and returns the same rows: only the amount of data the join moves changes.

The warning is about the **left** side of the join, the pipeline the `join` operator sits in. It does not look at the right side: a `let` or sub-query on the right that ends in `project`, `summarize` or `distinct` is narrow already, and making it narrower changes nothing here. The right side's shape does not matter; to clear the warning, narrow the left side before the `join`.

It fires when the `join` comes before any `project`, `project-keep`, `project-away`, `summarize`, `distinct` or `count` in that pipeline, and a `project` comes after it. It stays quiet when no `project` follows the `join`, when the pipeline starts from a `let` (or a `union` of `let`s) that ends in one of those operators, and for `summarize` itself, which returns only the columns it names.

## Example

```kusto
let Admins = IdentityInfo
| summarize by AccountUPN;               // the right side is already narrow
AzureActivity                            // the left side carries every column
| join kind=inner Admins on $left.Caller == $right.AccountUPN
| project TimeGenerated, Caller, OperationNameValue
```

The warning points at the `join`: `AzureActivity` carries every column into it, however small `Admins` is.

## How to fix

Project the columns the rest of the query needs on the left side, before the `join`:

```kusto
let Admins = IdentityInfo
| summarize by AccountUPN;
AzureActivity
| project TimeGenerated, Caller, OperationNameValue
| join kind=inner Admins on $left.Caller == $right.AccountUPN
```

Keep every column the `join` key and the later operators read. If the query needs all columns, for instance `arg_max(TimeGenerated, *)`, leave it: the warning is a hint about cost, and a rule can accept it.
