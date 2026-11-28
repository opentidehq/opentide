# datadog_pipelines_only

A Datadog search uses Observability Pipelines syntax (`_exists_:`, `_missing_:`, a quoted field name), which log search does not read the same way.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Observability Pipelines (VRL) has its own search dialect. In log search, existence is `@attribute:*`, absence `-@attribute:*`, and a field name is written bare, with what needs it escaped.

## Example

```text
_exists_:service
"service.status":disabled
```

## How to fix

Write the log search form: `service:*`, `service.status:disabled` (as a tag) or `@service.status:disabled` (as an attribute).
