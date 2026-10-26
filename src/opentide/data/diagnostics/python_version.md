# python_version

The Python interpreter running opentide.

Reported by `opentide doctor`. Fails when it is older than 3.10.

## Example

```text
✓ Python 3.13.16 · python_version
```

## How to fix

Install Python 3.10 or later and reinstall opentide with it (`uv tool install opentide`, or `pipx install --python python3.12 opentide`).
