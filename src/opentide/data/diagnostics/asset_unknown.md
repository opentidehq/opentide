# asset_unknown

A `visibility.toml` log source or detector names an asset that `[[assets]]` does not declare.

Severity: warning. Reported by `opentide validate` (check `configuration`); the loaders log it and go on.

## Example

```toml
[[assets]]
name = "domain-controllers"
description = "Active Directory"
criticality = "high"

[[logsources]]
name = "Security events"
description = "Windows security log"
system = "splunk"
assets = ["domain-controller"]   # declared as domain-controllers
```

## How to fix

Correct the asset name, or declare the asset under `[[assets]]`.
