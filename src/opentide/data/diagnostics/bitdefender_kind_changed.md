# bitdefender_kind_changed

An update was refused because the block's kind differs from the GravityZone rule's.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). GravityZone cannot turn a YARA rule into a Basic rule or back, and `updateCustomRule` takes no `subtype`.

## Example

```yaml
configurations:
  bitdefender:
    # deployed as yara, now a detection block
    detection:
      target: process
```

## How to fix

Deploy the rule with a `DELETION` status first, then deploy it again with the new kind.
