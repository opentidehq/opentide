# harfanglab_yara_context

A YARA rule in a HarfangLab `yara.signature` sets a meta `context` HarfangLab's rules do not use.

Severity: warning. Reported by `opentide lint` (its `queries` check) on a HarfangLab rule (`harfanglab`) written in the signature form: a rule that is not `private` sets meta `context` to a value other than `file`, `memory`, `file,memory`, `file.pe`, `file.elf`, or `file.macho`. `opentide validate` does not fail on it. `file`, `memory`, and `file,memory` are the values HarfangLab's published rules use; `file.pe`, `file.elf`, and `file.macho` are what the decomposed form writes from `meta.os`. No HarfangLab document defines the key, so another value may be accepted and never scanned.

## Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: |
        rule Cmd_String {
          meta:
            context = "disk"   # not a HarfangLab context
          strings:
            $a = "cmd.exe" ascii
          condition:
            $a
        }
```

## How to fix

Set `context` to where the agent should scan: `file`, `memory`, or `file,memory`, or a file type (`file.pe`, `file.elf`, `file.macho`). Then run `opentide lint --check queries` again.

```yaml
          meta:
            context = "file,memory"
```
