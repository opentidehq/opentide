# compile_invalid_value

A setting in the rule's platform block holds a value the platform cannot use.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1.

## Example

```text
error[compile_invalid_value]: configurations.sentinel.alert.suppression is true
  ╭─▶ objects/rules/lsass-access.yaml
  ╰─ help: set it to false or a duration such as PT1H
```

## How to fix

Set the value the help names. Durations are ISO 8601 (`PT1H`, `P1D`).
