# harfanglab_yara_context

A HarfangLab YARA rule's meta `context` is not a comma-joined list of the scan contexts HarfangLab uses.

Severity: warning. Reported by `opentide lint` (its `queries` check) on a HarfangLab rule (`harfanglab`). In the signature form, a rule that is not `private` sets meta `context` to something other than a comma-joined list, without blanks, of `file`, `memory`, `file.pe`, `file.elf`, and `file.macho` (`file,memory` and `file.pe,memory` are lists), or to a value that is not a string (`context = 1`). In the decomposed form, the `context` deploy writes from `meta.context` and `meta.os` is checked the same way. `opentide validate` does not fail on it. `file`, `memory`, and `file,memory` are the values HarfangLab's published rules use; `file.pe`, `file.elf`, and `file.macho` are what the decomposed form writes for `file`. No HarfangLab document defines the key, so another value may be accepted and never scanned.

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

Set `context` to where the agent should scan: `file`, `memory`, or both (`file,memory`), or a file type (`file.pe`, `file.elf`, `file.macho`), joined with commas and no spaces. In the decomposed form, list them under `meta.context`. Then run `opentide lint --check queries` again.

```yaml
          meta:
            context = "file,memory"
```
