# bitdefender_criterion_shape

A criterion does not have `field` and exactly one of `is`, `contains` and `any`.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). `is` takes a string or an integer, `contains` a string, and `any` a non-empty list of strings or integers.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: process
      criteria:
        - field: Process.Name
          is: powershell.exe
          contains: "*shell*"
```

## How to fix

Keep one relation per criterion. Two conditions on one field are two criteria, which must both match.
