# yara_signature_alias

A `yara.signature` is a YAML alias instead of its own text.

Severity: error. Reported by `opentide validate` on any platform `yara` block (yara-1.0). Each block writes out the signature it deploys, so a change to one platform's YARA rule cannot silently change another's, and each is checked under its own platform profile.

## Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: &loader |
        rule Loader { condition: uint16(0) == 0x5A4D }
  bitdefender:
    yara:
      signature: *loader
```

## How to fix

Write the signature out in each block.
