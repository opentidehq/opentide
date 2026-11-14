# bitdefender_criteria_combination

The criteria combine fields or values GravityZone does not allow together.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). EDR-only and XDR-only fields or values are not mixed (`File.CreatedBy.*` with `File.MD5`, `rename` with `downloaded`). `File.Certificate*` needs `File.Name` or `File.FullPathName`. `Connection.Protocol` needs `Connection.Domain`. An XDR detection uses `alert` or an operation criterion, not both.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: connection
      criteria:
        - field: Connection.Protocol
          is: smb
```

## How to fix

Add the field the pairing needs (`Connection.Domain`), or split EDR and XDR conditions into two rules.
