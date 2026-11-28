# datadog_curly_quote

A Datadog search holds a curly quote, which is not a quote: the words around it are searched as separate terms.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Only the straight double quote `"` delimits a phrase. Text pasted from a document often carries `“` and `”`, which Datadog searches as part of the words.

## Example

```text
@evt.name:“Console Login”
```

## How to fix

Use straight double quotes: `@evt.name:"Console Login"`.
