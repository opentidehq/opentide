# datadog_parse_error

The Datadog search does not parse: an unbalanced bracket, a dangling operator, an empty group, a field with no value, two modifiers in a row, or an unclosed phrase.

Severity: error. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Datadog refuses the query. The engine reports the first fault only: what follows it is not checked. Modifiers do not stack (`--a`, `NOT NOT a`, `-NOT a`), a field needs a value after its colon, and a space between a field and its colon makes the field free text, so the colon starts nothing. Nesting deeper than 1,000 groups is the same error.

## Example

```text
service:(web OR api
@usr.email:
@session.view.count :> 3
```

## How to fix

Close the bracket, give the field a value, write one modifier, and put the colon right after the field: `service:(web OR api)`, `@session.view.count:>3`.
