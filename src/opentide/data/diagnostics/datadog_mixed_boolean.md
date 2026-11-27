# datadog_mixed_boolean

A Datadog search puts OR beside an AND, written or implied, without parentheses: AND binds tighter, as VRL reads it (unverified on Cloud SIEM).

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

In Datadog's search syntax, a space between two clauses is AND, and AND binds tighter than OR, so `service:x status:error OR warning` reads as `(service:x status:error) OR warning`: any log containing the word `warning` matches. The precedence is VRL's (the library behind Datadog's Observability Pipelines) and is not yet verified on Cloud SIEM, so this is a warning. The same holds inside a value group: `@SourceFileName:(*.exe OR *.rar *.7z)` asks for a name ending in both `.rar` and `.7z`.

## Example

```text
service:azure-service-bus status:error OR warning
```

## How to fix

Add parentheses to say which you mean: `service:azure-service-bus status:(error OR warning)`.
