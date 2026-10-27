# Detection objectives

Author objectives as `objective::1.0` YAML under `objects/objectives/`.

## Shape

- `metadata.uuid` is required. `metadata.schema` is `objective::1.0`.
- Linked threats are UUIDs under `objective.threats`.
- Signals, when present, are objects under `objective.signals` and each signal has its own `uuid`.
- Do not use `mdr::2.1` or a `Schemas/Templates` path. Generate a starting file with `opentide generate`.

## Check

```bash
opentide --json validate --strict
opentide --json lint --strict
```

Apply each finding's `fix.edits`, run `opentide explain <code>` for a finding without one, and repeat until the exit code is `0`.
