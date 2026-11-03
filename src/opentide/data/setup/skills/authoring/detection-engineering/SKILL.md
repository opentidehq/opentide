# Detection engineering

opentide content is three object families:

| Object | Schema | Directory |
|--------|--------|-----------|
| Threat | `threat::1.0` | `objects/threats/` |
| Objective | `objective::1.0` | `objects/objectives/` |
| Rule | `rule::1.1` | `objects/rules/` |

A rule's `detection_model` points at an objective. An objective lists threat UUIDs under `objective.threats`. A threat chains to another threat with `threat.chaining` entries of `relation` and `vector`.

Start a new object with `opentide new threat`, `opentide new objective` or `opentide new rule`, which write it from the current template. Platform settings live in `.opentide/configurations/platforms/<platform>.toml`, and a rule's platform block names its schema as `platform::<platform>::1.0`.

```bash
opentide --json validate --strict
opentide --json lint --strict
opentide generate
opentide deploy --dry-run --strategy PREVIEW --all
```

Loop until the checks pass: search what exists, draft, `opentide --json validate --strict` and apply each finding's `fix` (or read `opentide explain <code>`), then preview the deployment. Branch on the exit code and `failure.code`; follow `next_actions`. `opentide --json commands` lists every command and option. People review, merge and deploy.
