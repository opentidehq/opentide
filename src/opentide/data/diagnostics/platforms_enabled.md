# platforms_enabled

Which platforms the workspace enables.

Reported by `opentide doctor`. Warns when none is: rules validate but nothing deploys.

## Example

```text
✓ Enabled: sentinel · platforms_enabled
```

## How to fix

Enable one with `opentide setup platforms --<platform>` (`--sentinel`, `--splunk`, …).
