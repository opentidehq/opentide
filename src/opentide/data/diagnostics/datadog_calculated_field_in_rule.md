# datadog_calculated_field_in_rule

A detection rule's query names a calculated field (`#name`): real-time detection rules have none.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Calculated fields are defined in a Log Explorer view; a real-time detection rule evaluates incoming logs, which carry none. In a `.datadog` file (profile `search`) `#name` is allowed.

## Example

```text
#duration_ms:>500
```

## How to fix

Use the attribute the calculated field is computed from: `@duration:>500ms`.
