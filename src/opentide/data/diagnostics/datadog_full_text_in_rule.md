# datadog_full_text_in_rule

A detection rule's query searches every attribute with `*:term`, which Datadog documents for monitors, dashboards and notebooks, not for detection rules.

Severity: warning. Reported by the analysis engine on a Datadog log search: in an editor on a `.datadog` file (`opentide lsp start`, profile `search`), and, once the `datadog` platform lands, on a detection rule's queries (profile `rule`).

Datadog's search syntax page documents `*:term` for Log Management's monitor, dashboard and notebook queries; detection rules are not on that list. `*:*` (every event) is not reported. In a `.datadog` file (profile `search`) `*:term` is allowed.

## Example

```text
*:mimikatz
```

## How to fix

Name the attribute the term is in: `@process.command_line:*mimikatz*`.
