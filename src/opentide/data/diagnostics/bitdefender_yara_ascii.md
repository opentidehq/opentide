# bitdefender_yara_ascii

A Bitdefender YARA signature holds a character that is not ASCII.

Severity: error. Reported by `opentide validate` on a `bitdefender` block's `yara.signature` (bitdefender-1.0): GravityZone takes ASCII only. The analysis engine checks the signature under its Bitdefender profile and places the finding on the character; without the engine, `opentide validate` still reports it on `yara.signature`. `opentide validate query --platform bitdefender` reports it in a `.yar` file. Deploy refuses the rule.

## Example

```yaml
configurations:
  bitdefender:
    yara:
      signature: |
        rule Loader {
          meta:
            description = "Stage-1 loader — config blob"
          condition:
            true
        }
```

## How to fix

Replace the character with ASCII (`-` for `—`), or match it as a hex string (`{ E2 80 94 }`), then run `opentide validate` again.
