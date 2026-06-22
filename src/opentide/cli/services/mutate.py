"""Mutation services for the CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentide.core.logging import log

if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def run_mutate_all() -> None:
    """Run full mutation pipeline (Orchestration/mutate.py parity)."""
    from Engines.mutation import file_name, references, security_domain

    file_name.run()
    references.run()
    security_domain.run()


def run_mutate_promote(files: list[str] | None = None) -> None:
    """Promote MDR status for modified files."""
    from pathlib import Path

    from Engines.modules.deployment import DeploymentStrategy, modified_mdr_files
    from Engines.mutation.promotion import PromoteMDR

    plan = DeploymentStrategy.load_from_environment()
    raw_targets = files if files is not None else modified_mdr_files(plan)
    targets = [Path(p) for p in raw_targets]
    PromoteMDR().promote(targets)


def run_mutate_rename() -> None:
    from Engines.mutation import file_name

    file_name.run()


def run_mutate_references() -> None:
    from Engines.mutation import references

    references.run()


def run_mutate_security_domain() -> None:
    from Engines.mutation import security_domain

    security_domain.run()


def run_mutate(
    ctx: CliContext,
    *,
    action: str | None = None,
    files: list[str] | None = None,
) -> dict[str, object]:
    """Entry point for mutate command."""
    ctx.apply_environment()

    if action is None:
        run_mutate_all()
        if not ctx.json_output:
            log("SUCCESS", "Completed mutation toolchain")
        return {"message": "Full mutation pipeline completed"}

    if action == "promote":
        run_mutate_promote(files)
        return {"message": "Promotion completed", "action": action}
    if action == "rename":
        run_mutate_rename()
        return {"message": "Rename completed", "action": action}
    if action == "references":
        run_mutate_references()
        return {"message": "References completed", "action": action}
    if action == "security-domain":
        run_mutate_security_domain()
        return {"message": "Security domain completed", "action": action}

    raise ValueError(f"Unknown mutate action: {action}")
