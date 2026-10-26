# compile_empty_block

A block the rule needs is present but empty, so the platform cannot read a value from it.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. An empty YAML block (`response:` with nothing under it) loads as nothing.

## Example

```text
error[compile_empty_block]: 'response' is empty, so Sentinel cannot read 'alert_severity'
  ╭─▶ objects/rules/sentinel-kql-rule.yaml
  ╰─ help: set response.alert_severity, or configurations.sentinel.alert.severity
```

## How to fix

Fill the block with the keys the help names, or delete it when the platform block sets the value itself (`configurations.sentinel.alert.severity`).
