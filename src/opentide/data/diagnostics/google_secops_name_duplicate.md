# google_secops_name_duplicate

Two enabled Google SecOps blocks resolve to one YARA-L rule name.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). The rule name is the block's `name`, else the rule's title lower-cased with runs of other characters as `_`. Names are compared case-insensitively: a composite rule that matches a producer by `detection.detection.rule_name` would match both, and Google's own tooling treats names as unique regardless of case.

## Example

```yaml
# rule-a.yaml: name: Password spray
# rule-b.yaml:
configurations:
  google_secops:
    name: PASSWORD_SPRAY
```

## How to fix

Give one of the blocks its own `configurations.google_secops.name`, or rename one of the rules.
