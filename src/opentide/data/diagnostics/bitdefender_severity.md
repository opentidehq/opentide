# bitdefender_severity

The block `severity` is not `Low`, `Medium` or `High`.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). GravityZone has three severities, spelled with a capital letter. Without `severity`, deploy derives it from `response.alert_severity`.

## Example

```yaml
configurations:
  bitdefender:
    severity: Critical
```

## How to fix

Use `Low`, `Medium` or `High`, or remove the key.
