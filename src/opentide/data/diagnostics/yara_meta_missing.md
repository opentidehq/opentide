# yara_meta_missing

A YARA rule in a HarfangLab `yara.signature` has no meta `context`, which the HarfangLab profile recommends on every rule that is not private.

Severity: warning. Reported by `opentide lint` (its `queries` check) on a HarfangLab rule (`harfanglab`) written in the signature form: a rule that is not `private` has no `meta:` section, or one without `context`. `opentide validate` does not fail on it. Deploy sends the signature verbatim and adds no meta, so the agent receives the rule without saying where to scan.

## Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: |
        rule Cmd_String {
          strings:
            $a = "cmd.exe" ascii
          condition:
            $a
        }
```

## How to fix

Add a `meta:` section with `context` to the rule (`file`, `memory`, or `file,memory`), then run `opentide lint --check queries` again. A `private` helper rule needs none.

```yaml
        rule Cmd_String {
          meta:
            context = "file"
          strings:
            $a = "cmd.exe" ascii
          condition:
            $a
        }
```
