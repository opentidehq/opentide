# rule_status_unknown

A `sharing.toml` block lists a rule status your configuration does not declare.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

## Example

```toml
rule_statuses = ["PRODUCTON"]
```

## How to fix

Use a status from your deployment configuration's statuses.
