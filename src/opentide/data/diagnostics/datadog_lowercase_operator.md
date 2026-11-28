# datadog_lowercase_operator

A lower-case `and`, `or` or `not` stands between field clauses or in a value group, where Datadog reads it as a search term, not an operator.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Operators are upper case only. A lower-case `or` between two field clauses is a free-text term joined to both by AND; in a value group it is a value. Between free-text words it is just a word, and is not reported (`not enough attributes`).

## Example

```text
@login_type:(k OR n or E)
```

## How to fix

Write the operator in upper case: `@login_type:(k OR n OR E)`.
