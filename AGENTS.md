# Agent Fleet Orchestration — Project TideKit

**OpenTide** (`opentide`) is the PyPI-packaged successor to [CoreTide](https://github.com/OpenTideHQ/CoreTide). This document governs how autonomous agents execute the TideKit transformation programme.

**Mandatory:** All TideKit **implementation** pull requests target [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) only. [OpenTideHQ/CoreTide](https://github.com/OpenTideHQ/CoreTide) issues track programme work; the CoreTide repo remains the spec/source baseline — do not open feature or refactor PRs there (docs and issue updates only).

> **Tracking issues**: [Epic #60](https://github.com/OpenTideHQ/CoreTide/issues/60), phases [#61–#71](https://github.com/OpenTideHQ/CoreTide/issues?q=is%3Aissue+milestone%3A%22Project+TideKit%22).

## Fleet Ground Rules

| Rule | Detail |
|------|--------|
| Implementation repo | [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) **only** — never TideKit code on CoreTide |
| Tracking / baseline | [OpenTideHQ/CoreTide](https://github.com/OpenTideHQ/CoreTide) issues + spec baseline; CoreTide PRs limited to docs/issues |
| Base branch | `development` (in **opentide**) |
| One phase = one agent = one PR | Phases 6 (#67) and 7 (#68) may run in parallel after Phase 5 |
| Start gate | All **Depends on** phases merged |
| PR | Target `development` on **opentide**; link/close the CoreTide phase issue (#61–#71) |

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
python -c "from opentide import OpenTide"

# Phase 5 (#66)
uv sync --group dev && uv run python -c "from opentide import OpenTide"

# Phase 9 (#71)
uv sync --group dev && uv run pytest --cov=opentide --cov-fail-under=80
```

## Developer toolchain (uv + ruff + ty)

Dependency management uses [uv](https://docs.astral.sh/uv/). A lockfile (`uv.lock`) is committed; sync before any local work:

```bash
uv sync --group dev          # install runtime + dev deps into .venv
uv run pytest tests/ -v      # run tests
uv run ruff check src tests  # lint
uv run ruff format src tests # format
uv run ty check src/opentide # Astral ty (sole type checker)
```

CI runs `uv sync --group dev` on Python **3.10–3.14**. **ty** is the type checker in CI and pre-commit; **ruff** handles lint and format.

## Repository layout

```
src/opentide/     # PyPI package (models, CLI, MCP, bundled data)
src/Engines/      # Runtime deployers/validators (shipped in wheel; migrating into opentide)
tests/
docs/
scripts/
```

Bundled data lives under `src/opentide/data/` (configurations, vocabulary, external, log_sources). There are **no** legacy root folders (`Configurations/`, `Framework/`, `External/`, `Orchestration/`, `Engines/` at repo root).

Client detection repositories get CI from **`opentide init --ci github|gitlab|azure`** or **`opentide ci generate`** — generated pipeline files call the `opentide` CLI via PyPI install. Do not copy or maintain CoreTide-coupled workflow trees in client repos.

Structured logging lives in `opentide.core.logging` (structlog + Rich). Legacy `src/Engines/modules/logs.py` is a thin shim — new code must import from `opentide.core.logging`.

Full commands in each issue and [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

## Backlog sync (mandatory)

Every agent **must** keep [OpenTideHQ/CoreTide](https://github.com/OpenTideHQ/CoreTide) TideKit issues current while working in this repo. Planning stays on CoreTide; implementation lands here.

### When to update

| Event | Action |
|-------|--------|
| Open a PR | Comment on the parent phase issue (#61–#71) with PR URL and checklist progress |
| Push significant progress | Update the same phase-issue comment or add a short progress reply |
| Merge a phase PR to `development` | Mark phase **Merged** on its issue; refresh epic [#60](https://github.com/OpenTideHQ/CoreTide/issues/60) orchestration snapshot |
| Blocked on human action | Note blocker on epic #60 and the phase issue |

### How

```bash
gh issue comment <phase-issue> --repo OpenTideHQ/CoreTide --body "$(cat <<'EOF'
## Status: PR open

**PR**: https://github.com/OpenTideHQ/opentide/pull/<N>
**Branch**: `<branch>`
**Phase progress**:
- [x] CDM removed from configs
- [ ] IndentFullDumper consolidated
- [ ] CI green

**Verification**: `pytest tests/ -v` — 4 passed
EOF
)"
```

After a phase merges, post a fresh orchestration snapshot on epic #60 (see [`.github/instructions/backlog-sync.instructions.md`](.github/instructions/backlog-sync.instructions.md)).

### Labels

Keep `tidekit` and `agent-ready` on groomed phase issues. Do not remove labels when commenting.

### Status values

Use exactly one of: **Not started** · **In progress** · **PR open** · **Merged**

Do **not** close phase issues until the corresponding work is merged to `development` in this repo.

## Supporting Docs

- [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
- [`.github/instructions/backlog-sync.instructions.md`](.github/instructions/backlog-sync.instructions.md)
- [`.github/instructions/tidekit-phase.instructions.md`](.github/instructions/tidekit-phase.instructions.md)
- [`.github/instructions/testing.instructions.md`](.github/instructions/testing.instructions.md)
- [`docs/migration/MIGRATION.md`](docs/migration/MIGRATION.md)
