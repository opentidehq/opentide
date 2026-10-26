# scope_no_match

A `--file`, `--uuid` or `--type` selection matched no object, so nothing was validated.

Severity: error. Reported by `opentide validate`. `opentide share` also sets it as `failure.code` and `preflight` when no sharing target matches `--target` or none is enabled.

## Example

```text
opentide validate --file objects/rules/sentinel-kql-rul.yaml
```

## How to fix

Fix the path, file name or UUID. A path matches only that file; a bare file name matches every object file with that name. Every `--file` target must match. For `share`, name a target `opentide share targets` lists, and enable it in `sharing.toml`.
