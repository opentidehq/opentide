---
name: opentide-detection-objective
description: >-
  Author an opentide detection objective (objective::1.0 YAML under objects/objectives/):
  its required metadata, linked threat UUIDs and signals, and the validate and lint loop
  that checks it. Use when creating or editing a detection objective.
---

# Detection objectives

Author objectives as `objective::1.0` YAML under `objects/objectives/`.

## Shape

- `metadata.uuid` is required. `metadata.schema` is `objective::1.0`.
- Linked threats are UUIDs under `objective.threats`.
- Signals, when present, are objects under `objective.signals` and each signal has its own `uuid`.
- Start a new objective with `opentide new objective`, which writes it from the current template.

## Check

```bash
opentide --json validate --strict
opentide --json lint --strict
```

Apply each finding's `fix.edits`, run `opentide explain <code>` for a finding without one, and repeat until the exit code is `0`.
