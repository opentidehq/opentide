# bitdefender_severity_collapsed

`response.alert_severity` is `Critical` or `Informational`, which GravityZone sends as `High` or `Low`.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a rule with a `bitdefender` block that sets no `severity` (bitdefender-1.0). GravityZone has three severities: deploy sends `Critical` as `High` and `Informational` as `Low`. It is an advisory: the rule validates and deploys.

## Example

```yaml
response:
  alert_severity: Critical
configurations:
  bitdefender:
    status: PRODUCTION
```

## How to fix

Set `configurations.bitdefender.severity` to `Low`, `Medium` or `High` to choose the GravityZone level, or accept the mapping.
