# datadog_concurrent_modification

The Datadog rule changed between deploy's read and its update.

Severity: error. Reported by `opentide deploy` on a `datadog` block (`platform::datadog::1.0`). An update sends the `version` the `GET` returned; Datadog answers a stale version with `401`, which opentide reports as this code rather than as a refused key. Someone or something changed the rule meanwhile.

## Example

```text
datadog_concurrent_modification: Datadog rule abc-def-ghi changed after deploy read it (HTTP 401 on the update, which carries the version read)
```

## How to fix

Deploy again. If the rule keeps changing, find what else edits it (the UI, Terraform) and stop it.
