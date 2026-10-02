# Detection engineering

OpenTide content is three object families:

| Object | Schema | Directory |
|--------|--------|-----------|
| Threat | `threat::1.0` | `objects/threats/` |
| Objective | `objective::1.0` | `objects/objectives/` |
| Rule | `rule::1.0` | `objects/rules/` |

A rule's `detection_model` points at an objective. An objective lists threat UUIDs under `objective.threats`. A threat chains to another threat with `threat.chaining` entries of `relation` and `vector`.

Do not create `Schemas/Templates`, `Configurations/systems`, or `mdr::2.1` documents. `opentide generate` writes the current templates.

```bash
opentide validate --strict
opentide lint --strict
opentide generate
opentide deploy --dry-run
```
