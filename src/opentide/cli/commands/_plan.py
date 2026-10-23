"""The ``--plan`` option removed in 0.17.0, still refused by name on validate and deploy."""

from __future__ import annotations

from typing import Any

from opentide.cli.output import emit_error

REMOVED_PLAN_HELP = "Removed in 0.17.0; use --strategy"


def refuse_removed_plan(cli: Any, plan: str | None) -> None:
    if plan is not None:
        from opentide.models.deployment_enums import removed_plan_message

        emit_error(cli, removed_plan_message(plan, option=True), exit_code=2)
