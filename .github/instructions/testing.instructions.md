---
description: "Use when writing, running, or reviewing tests for opentide. Covers pytest, coverage, behaviour inventory from Phase 4."
applyTo: "tests/**/*.py"
---

# Testing Instructions

Plan: [`docs/TEST_PLAN.md`](../../docs/TEST_PLAN.md)

Phase 4 ([#65](https://github.com/OpenTideHQ/CoreTide/issues/65)) creates `docs/migration/behaviour-inventory.md`. Phase 9 ([#71](https://github.com/OpenTideHQ/CoreTide/issues/71)) implements pytest with ≥80% core coverage.

## Commands

```bash
pip install -e ".[dev]"
pytest --cov=opentide --cov-fail-under=80
ruff check src/opentide tests/
mypy --strict src/opentide/core
```

## Layout

`tests/{test_core,test_models,test_platforms,test_validation,test_generation,test_cli,fixtures}/`

## Behaviour inventory

Parametrise tests from `docs/migration/behaviour-inventory.md` — not closed issues #59/#70.

## Capability invariants

7 deployers, 5 validators. `crowdstrike` and `harfanglab`: `can_validate is False`.

## CLI tests

Use `typer.testing.CliRunner` against `opentide.cli.app`.
