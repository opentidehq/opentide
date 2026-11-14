# bitdefender_name_duplicate

Two enabled Bitdefender blocks resolve to the same GravityZone rule name.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). The GravityZone name is the block's `name`, else the rule's `name`, normalised and cut at 128 characters. GravityZone refuses a second rule with one name in a company, so the second deploy would fail with `bitdefender_name_conflict`.

## Example

```yaml
# rule-a.yaml and rule-b.yaml, both:
name: Office application spawns encoded PowerShell
configurations:
  bitdefender:
    enabled: true
```

## How to fix

Give one of the blocks its own `configurations.bitdefender.name`, or rename one of the rules.
