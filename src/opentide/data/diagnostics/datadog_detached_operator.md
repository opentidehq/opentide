# datadog_detached_operator

A Datadog exclusion `-` is followed by a space.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

The exclusion is written against what it excludes. With a space after it, a reader cannot tell what is excluded, and the docs never write it so.

## Example

```text
- @login_type:k
```

## How to fix

Remove the space: `-@login_type:k`.
