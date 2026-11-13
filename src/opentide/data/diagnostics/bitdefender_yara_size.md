# bitdefender_yara_size

A Bitdefender YARA signature is longer than 30,000 characters.

Severity: error. Reported by `opentide validate` on a `bitdefender` block's `yara.signature` (bitdefender-1.0): GravityZone takes at most 30,000 characters. The analysis engine checks the signature under its Bitdefender profile; without the engine, `opentide validate` still reports it on `yara.signature`. `opentide validate query --platform bitdefender` reports it in a `.yar` file. Deploy refuses the rule.

## Example

```yaml
configurations:
  bitdefender:
    yara:
      signature: |
        rule Loader {
          strings:
            $a01 = "..."   # thousands of strings, 30,001 characters in all
          condition:
            any of them
        }
```

## How to fix

Shorten the signature: drop comments and unused strings, or split its rules across several Tide rules, then run `opentide validate` again.
