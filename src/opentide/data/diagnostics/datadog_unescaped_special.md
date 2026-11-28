# datadog_unescaped_special

A Datadog search term holds an unescaped `!`, `<` or `>`, or a value starts with an unescaped `-`, which Datadog reads as an exclusion: escape it with `\`.

Severity: error. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Datadog's search syntax reserves `!`, `<` and `>` (comparisons go right after a field's colon: `@x:>=5`), and a `-` before a value excludes it. A negative number in a comparison is fine (`@x:>-1`).

## Example

```text
foo!bar
@x:-1
```

## How to fix

Escape the character (`foo\!bar`, `@x:\-1`) or quote the value (`@x:"-1"`). To exclude, put `-` before the field: `-@x:1`.
