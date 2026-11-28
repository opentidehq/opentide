# datadog_wildcard_in_phrase

A `*` or `?` touches a word inside a quoted phrase, where it is punctuation, not a wildcard.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Wildcards work in terms only. Inside quotes, `"*mimikatz*"` searches for the word `mimikatz`, with the asterisks as punctuation.

## Example

```text
"*mimikatz*"
```

## How to fix

Take the wildcard out of the quotes, escaping any space: `*mimikatz*`, `*my\ test*`.
