# Detection engineering

opentide content is three object families:

| Object | Schema | Directory |
|--------|--------|-----------|
| Threat | `threat::1.0` | `objects/threats/` |
| Objective | `objective::1.0` | `objects/objectives/` |
| Rule | `rule::1.0` | `objects/rules/` |

A rule's `detection_model` points at an objective. An objective lists threat UUIDs under `objective.threats`. A threat chains to another threat with `threat.chaining` entries of `relation` and `vector`.

Do not create `Schemas/Templates`, `Configurations/systems`, or `mdr::2.1` documents. `opentide generate` writes the current templates.

```bash
opentide --json validate --strict
opentide --json lint --strict
opentide generate
opentide deploy --dry-run --strategy PREVIEW --all
```

Loop until the checks pass: search what exists, draft, `opentide --json validate --strict` and apply each finding's `fix` (or read `opentide explain <code>`), then preview the deployment. Branch on the exit code and `failure.code`; follow `next_actions`. `opentide --json commands` lists every command and option. People review, merge and deploy.
