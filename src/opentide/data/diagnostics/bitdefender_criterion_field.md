# bitdefender_criterion_field

A criterion's `field` does not belong to the block's `target`.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). Each target has its own fields in Bitdefender's criteria catalogue: `process` has `Process.*`, `file` has `File.*`, `connection` has `Connection.*` and `registry` has `Registry.*`. A field the catalogue does not list for any other target is a warning. The alert filter (`detection`) is never a criterion, on any target: write it as the block's `alert`.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: process
      criteria:
        - field: Process.Hash
          is: 44d88612fea8a8f36de82e1278abb02f
```

## How to fix

Use a field of the target, as the catalogue spells it (`Process.MD5`), or change the target.
