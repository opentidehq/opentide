# datadog_regex

A Datadog search term holds `~` or `^`: the search syntax has no regular expression, fuzzy or boost operator.

Severity: error. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Lucene's `foo~2` (fuzzy) and `foo^2` (boost) are not Datadog syntax, and `/…/` is not a regular expression: `/` is an ordinary character.

## Example

```text
@msg:foo~2
```

## How to fix

Use wildcards (`@msg:foo*`), or escape the character to search for it (`@msg:foo\~2`).
