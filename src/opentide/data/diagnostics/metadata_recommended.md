# metadata_recommended

An object has no `metadata.author` or `metadata.organisation`.

Severity: note. Reported by `opentide lint` (metadata check). The editor and `opentide tui` report the same finding as `missing_author` and `missing_organisation`.

## Example

```yaml
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  # author and organisation are missing
```

## How to fix

Add the missing keys under `metadata`. They are optional, so the note never fails a run, `lint --strict` included, and prints only with `--verbose`. To require them, set `severity = "warning"` or `"error"` under `[metadata]` in `.opentide/configurations/lint.toml`; to stop asking for them, set `required = []`.
