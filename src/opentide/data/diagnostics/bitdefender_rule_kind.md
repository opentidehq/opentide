# bitdefender_rule_kind

A Bitdefender block sets both `detection` and `yara`, or neither.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). A GravityZone custom rule is one kind: a Basic rule (`detection`, a list of criteria) or a YARA rule (`yara`, a signature). An `exclusion` key is unknown: GravityZone exclusion rules are not opentide rules, and deploy never creates, updates or deletes one.

## Example

```yaml
configurations:
  bitdefender:
    status: STAGING
    detection:
      target: process
      criteria:
        - field: Process.Name
          is: mshta.exe
    yara:
      signature: |
        rule A { condition: filesize < 10 }
```

## How to fix

Keep one kind per rule. Split a Basic rule and a YARA rule into two opentide rules; manage exclusions in the GravityZone console.
