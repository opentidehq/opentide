"""CLI runtime context and environment wiring."""

from __future__ import annotations

import contextvars
import os
from dataclasses import dataclass, field
from pathlib import Path

from opentide.core.root import get_data_root, get_repo_root

_cli_context: contextvars.ContextVar[CliContext | None] = contextvars.ContextVar(
    "opentide_cli_context", default=None
)


@dataclass
class CliContext:
    """Shared CLI state propagated through Typer callbacks."""

    repo: Path = field(default_factory=get_repo_root)
    data: Path | None = None
    json_output: bool = False
    debug: bool = False
    no_color: bool = False
    show_banner: bool = True

    def apply_environment(self) -> None:
        """Push context flags into process environment for engine modules."""
        os.environ["OPENTIDE_REPO_ROOT"] = str(self.repo)
        if "OPENTIDE_TIDE_WORKSPACE" not in os.environ:
            os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(self.repo)
        get_repo_root.cache_clear()
        from opentide.core.index_manager import IndexManager

        IndexManager._cache = None
        if self.data is not None:
            os.environ["OPENTIDE_DATA_ROOT"] = str(self.data)
        elif "OPENTIDE_DATA_ROOT" not in os.environ:
            os.environ["OPENTIDE_DATA_ROOT"] = str(get_data_root())
        if self.debug:
            os.environ["DEBUG"] = "True"
            os.environ["DEBUG_ENABLED"] = "1"
        if self.no_color:
            os.environ["NO_COLOR"] = "1"
            os.environ["FORCE_COLOR"] = "0"

    def activate(self) -> None:
        """Register this context for nested Typer subcommand resolution."""
        _cli_context.set(self)

    def set_deployment_plan(self, plan: str | None) -> None:
        if plan is not None:
            os.environ["DEPLOYMENT_PLAN"] = plan.upper()


def get_context(ctx: object | None = None) -> CliContext:
    """Extract CliContext from contextvar or a Typer context object."""
    cached = _cli_context.get()
    if cached is not None:
        return cached
    from typer import Context

    if isinstance(ctx, Context):
        current: Context | None = ctx
        while current is not None:
            obj = current.obj
            if isinstance(obj, CliContext):
                return obj
            parent = current.parent
            current = parent if isinstance(parent, Context) else None
    raise TypeError("CLI context not initialised")
