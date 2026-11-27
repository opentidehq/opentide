# datadog_rule_default

The id a deployment state names is a Datadog default rule, which opentide never changes.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). Datadog ships and maintains default rules (`isDefault: true`); they can be enabled and tuned, but not rewritten or deleted through opentide. Deploy checks before any write and refuses.

## Example

```text
datadog_rule_default: Datadog rule def-000-u7q is a default rule, which opentide never changes or deletes
```

## How to fix

Remove the id from `.opentide/states/deployment/<uuid>.json`: the next deploy creates a rule of its own.
