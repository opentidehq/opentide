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
