# datadog_unescaped_colon

A Datadog search value holds an unescaped `:`, which Datadog's docs say to escape.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

A field is everything before the first unescaped colon, so a colon in the value is ambiguous; Datadog's docs list `:` among the characters to escape, though its own content does not always. A value of `tags` is no exception: the log docs write `tags:(env\:prod OR env\:test)`.

## Example

```text
@usr.id:system:serviceaccount:x
```

## How to fix

Escape the colons: `@usr.id:system\:serviceaccount\:x`, or quote the value.
