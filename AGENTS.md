# Agent Fleet Orchestration — Project TideKit

**OpenTide** (`opentide`) is the PyPI-packaged successor to [CoreTide](https://github.com/OpenTideHQ/CoreTide). This document governs how autonomous agents execute the TideKit transformation programme.

> **Tracking issues**: [Epic #60](https://github.com/OpenTideHQ/CoreTide/issues/60), phases [#61–#71](https://github.com/OpenTideHQ/CoreTide/issues?q=is%3Aissue+milestone%3A%22Project+TideKit%22).

## Fleet Ground Rules

| Rule | Detail |
|------|--------|
| Base branch | `development` |
| One phase = one agent = one PR | Phases 6 (#67) and 7 (#68) may run in parallel after Phase 5 |
| Start gate | All **Depends on** phases merged |
| PR | Target `development`, `Closes #<issue>` |

## Phase DAG

```
#61 → #62 → #63 → #64 → #65 → #66 ─┬→ #67 ─┐
                                    └→ #68 ─┴→ #69 → #71
```

| Phase | Issue | Start gate |
|-------|-------|------------|
| 0 | [#61](https://github.com/OpenTideHQ/CoreTide/issues/61) | immediately |
| 1 | [#62](https://github.com/OpenTideHQ/CoreTide/issues/62) | #61 |
| 2 | [#63](https://github.com/OpenTideHQ/CoreTide/issues/63) | #62 |
| 3 | [#64](https://github.com/OpenTideHQ/CoreTide/issues/64) | #63 |
| 4 | [#65](https://github.com/OpenTideHQ/CoreTide/issues/65) | #64 |
| 5 | [#66](https://github.com/OpenTideHQ/CoreTide/issues/66) | #65 |
| 6 | [#67](https://github.com/OpenTideHQ/CoreTide/issues/67) | #66 |
| 7 | [#68](https://github.com/OpenTideHQ/CoreTide/issues/68) | #66 |
| 8 | [#69](https://github.com/OpenTideHQ/CoreTide/issues/69) | #67 + #68 |
| 9 | [#71](https://github.com/OpenTideHQ/CoreTide/issues/71) | #69 |

[#70](https://github.com/OpenTideHQ/CoreTide/issues/70) is a closed duplicate of #65.

## Branch Naming

`refactor/tidekit-phase<N>-<slug>` or `feat/tidekit-phase<N>-<slug>` — see each issue's Agent Execution Contract.

## Conventional Commits

`<type>(<scope>): <description>` — types: feat, fix, refactor, docs, chore, test, ci.

## Platform Capability Matrix (7 deployers / 5 validators)

| Platform | Deploy | Query validate |
|----------|:------:|:--------------:|
| Sentinel | ✅ | ✅ KQL |
| Defender | ✅ | ✅ KQL |
| Splunk | ✅ | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL |
| Carbon Black | ✅ | ✅ Lucene |
| CrowdStrike | ✅ | ❌ |
| HarfangLab | ✅ | ❌ |

## Agent Workflow

1. Read epic #60 and lowest unblocked phase issue
2. Rebase on `development`, create contract branch
3. Implement acceptance criteria only
4. Run verification commands
5. Open PR with `Closes #<N>`
6. Stop — do not bundle phases

## Verification by Phase

```bash
# Phase 0 (#61)
rg -i '\bcdm\b|\bbdr\b' --glob '!*.md' | wc -l
python -c "from Engines.modules.tide import DataTide"

# Phase 5 (#66)
pip install -e . && python -c "from opentide import OpenTide"

# Phase 9 (#71)
pip install -e ".[dev]" && pytest --cov=opentide --cov-fail-under=80
```

Full commands in each issue and [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

## Supporting Docs

- [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
- [`.github/instructions/tidekit-phase.instructions.md`](.github/instructions/tidekit-phase.instructions.md)
- [`.github/instructions/testing.instructions.md`](.github/instructions/testing.instructions.md)
- [`docs/migration/MIGRATION.md`](docs/migration/MIGRATION.md)
