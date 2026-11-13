# recommended_field_missing

A field the templates ask for is missing; `opentide validate` accepts the object without it.

Severity: note. Reported by `opentide lint` (recommended check). Today it is a rule's `configurations` or `response`. The editor and `opentide tui` report the same finding from the analysis engine, as information, and follow `[recommended]` too.

## Example

```yaml
name: Suspicious sign-in
metadata:
  uuid: 00000000-0000-4000-8001-000000000002
  schema: rule::1.0
# no configurations: nothing to deploy yet
# no response: no alert guidance for the analyst
```

## How to fix

Add the field when the rule is ready for it: `configurations` with a block per platform to deploy to, `response` with the alert guidance. The note never fails a run, `lint --strict` included, and prints only with `--verbose`. To require them, set `severity = "warning"` or `"error"` under `[recommended]` in `.opentide/configurations/lint.toml`; to stop reporting them, set `enabled = false`.
