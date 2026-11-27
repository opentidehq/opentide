# datadog_range

A Datadog range is malformed (a missing bound, a lower-case `to`), or mixes an inclusive and an exclusive bound.

Severity: error (a malformed range); warning (mixed bounds). Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

A range is `[low TO high]` (inclusive) or `{low TO high}` (exclusive), with `TO` in upper case and `*` for an open end. A range that is never closed, or has no `TO`, is an error. `[1 TO 5}`, which mixes the two, is a warning: Datadog does not document it.

## Example

```text
@http.status_code:[400 to 499]
@http.status_code:[400 TO 499}
```

## How to fix

Write `TO` in upper case and the same bracket on both ends: `@http.status_code:[400 TO 499]`.
