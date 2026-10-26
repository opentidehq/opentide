# platform_sdk

Each enabled platform's SDK imports.

Reported by `opentide doctor`. Fails when it does not, with `subject` naming the platform.

## Example

```text
✗ splunk: cannot import splunklib (ModuleNotFoundError) · platform_sdk
  → pip install --force-reinstall opentide
```

## How to fix

Reinstall opentide with the command it prints, in a clean environment (`uv tool install --reinstall opentide` for a uv tool install). The platform SDKs are dependencies of opentide, so a failed import means a broken or mixed environment.
