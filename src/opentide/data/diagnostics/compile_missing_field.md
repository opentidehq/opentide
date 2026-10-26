# compile_missing_field

A rule's Sentinel block lacks a setting Sentinel needs to build the alert rule.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. The message names the key (`configurations.sentinel.grouping.alert is missing`) and the help says when it is required.

## Example

```text
error[compile_missing_field]: configurations.sentinel.scheduling.frequency is missing
  ╭─▶ objects/rules/lsass-access.yaml
  ╰─ help: required unless scheduling.nrt is true
```

## How to fix

Add the key under `configurations.sentinel` in the rule. The generated rule template, and a rule from `opentide new rule --platform sentinel`, show each one with its default.
