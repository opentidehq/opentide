---
name: opentide-detection-objective
description: >-
  Shape and checks for opentide detection objectives (objective::1.0 YAML under
  objects/objectives/). Use when creating or editing an objective; pair with the
  opentide-objective skill for signal and methodology authoring.
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

For signals, methodology and data contracts, install the full authoring skill: `opentide setup skills --install opentide-objective`.
