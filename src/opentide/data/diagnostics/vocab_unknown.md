# vocab_unknown

A value is not in the vocabulary its field uses.

Severity: error. Reported by `opentide validate` (schema check).

## Example

```yaml
metadata:
  tlp: clearr          # tlp::1.0 has clear, green, amber, amber+strict, red
```

## How to fix

Use a value from the vocabulary the label names. When a close value exists, `help` names it and `fix` carries the edit; the edit is marked `safe` only when the two spell the same word (they differ in case, spaces, `-` or `_`) and hold no digit, so an ATT&CK id is never replaced unreviewed. Your editor completes vocabulary values from the generated schemas (`opentide setup vscode`).
