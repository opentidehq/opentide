# opentide_latest

Whether PyPI has a newer opentide release than the one installed.

Reported by `opentide doctor`. Warns when a newer release exists or PyPI did not answer (3-second timeout, through the proxy); skipped with `--offline`.

## Example

```text
! opentide 0.18.0 is available; 0.17.2 is installed · opentide_latest
  → pip install --upgrade opentide
```

## How to fix

Upgrade with the command it prints (or `uv tool upgrade opentide` for a uv tool install). Read the changelog first: a release can rename or deprecate a key.
