# exabeam_severity

The block `severity` is not `none`, `low`, `medium`, `high` or `critical`.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). Exabeam's severities are lower case. Without `severity`, deploy derives it from `response.alert_severity` (`Informational` is `none`).

## Example

```yaml
configurations:
  exabeam:
    severity: High
```

## How to fix

Use `none`, `low`, `medium`, `high` or `critical`, or remove the key.
