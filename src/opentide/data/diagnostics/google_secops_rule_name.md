# google_secops_rule_name

A Google SecOps block's `name` is not a YARA-L rule name.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). The name is written as `rule <name> {`: it must be an identifier, `[A-Za-z_][A-Za-z0-9_]*`, and not a YARA-L keyword such as `match` or `rule`. An empty `name` is derived from the rule's title instead.

## Example

```yaml
configurations:
  google_secops:
    name: password-spray   # a hyphen is not allowed
```

## How to fix

Write the name with letters, digits and underscores (`password_spray`), or remove `name` to use the one derived from the rule's title.
