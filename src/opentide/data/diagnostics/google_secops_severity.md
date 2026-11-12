# google_secops_severity

A Google SecOps block's `severity` or `priority` is not one of Google's values.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). Both are written into the rule's meta and must be `Info`, `Low`, `Medium`, `High` or `Critical`, Google's community spelling. `Informational` is opentide's alert severity, not Google's.

## Example

```yaml
configurations:
  google_secops:
    severity: Informational
```

## How to fix

Use `Info`, `Low`, `Medium`, `High` or `Critical`, or remove the key: `severity` is derived from `response.alert_severity`, and `priority` defaults to the severity.
