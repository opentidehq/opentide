# datadog_symbol_operator

`&&` or `||` stands between Datadog search clauses: Datadog's docs list them as characters to escape; write AND or OR.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

VRL (Observability Pipelines) reads `&&` and `||` as AND and OR, and so does the engine, but Datadog's log search documents them as characters to escape, not as operators.

## Example

```text
source:okta && @evt.outcome:FAILURE
```

## How to fix

Write the operator: `source:okta AND @evt.outcome:FAILURE`.
