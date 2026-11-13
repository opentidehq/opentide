---
name: opentide-threat-vector
description: >-
  Author an opentide threat (threat::1.0 YAML under objects/threats/): its required
  metadata, narrative fields and chaining to other threats, and the validate and lint loop
  that checks it. Use when creating or editing a threat vector.
---

# Threats

Author threats as `threat::1.0` YAML under `objects/threats/`.

## Shape

- `metadata.uuid` is required. `metadata.schema` is `threat::1.0`.
- Narrative fields live under `threat:`.
- Chain another threat with `threat.chaining`: a list of `{relation, vector}` entries. `vector` is the other threat's UUID. There is no commented `#chaining: #- key:` block.

## Check

```bash
opentide --json validate --strict
opentide --json lint --strict
```

Apply each finding's `fix.edits`, run `opentide explain <code>` for a finding without one, and repeat until the exit code is `0`.
