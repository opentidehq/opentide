# yara_signature_alias

A `yara.signature` is a YAML alias of text anchored elsewhere in the file instead of YARA written in the block.

Severity: error. Reported by `opentide validate` (its `schema` check) on a rule whose `configurations.harfanglab.yara.signature` or `configurations.bitdefender.yara.signature` is `*name` (yara-1.0). What a block deploys must be readable in the block: an alias makes a change to the anchored text, under any other key, change the deployed rule too, and a signature in two platform blocks is checked once under each platform's profile. The YAML loader cannot tell an alias from text written in place, so `opentide validate` reads the file's node graph.

## Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: &shared_yara |
        rule Cmd_String { condition: true }
  bitdefender:
    yara:
      signature: *shared_yara
```

## How to fix

Write the YARA text under each `signature` with a block scalar (`|`), then run `opentide validate` again.

```yaml
configurations:
  bitdefender:
    yara:
      signature: |
        rule Cmd_String {
          condition:
            true
        }
```
