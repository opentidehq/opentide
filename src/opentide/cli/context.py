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
    #: True when ``--repo`` was typed on the command line rather than inherited
    #: from ``OPENTIDE_REPO_ROOT``. An explicit path has to win over a stale
    #: ``OPENTIDE_TIDE_WORKSPACE`` export, or ``--repo`` silently does nothing.
    repo_explicit: bool = False

    def apply_environment(self) -> None:
        """Push context flags into process environment for engine modules."""
        os.environ["OPENTIDE_REPO_ROOT"] = str(self.repo)
        if self.repo_explicit or "OPENTIDE_TIDE_WORKSPACE" not in os.environ:
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
            # Rich reads any non-empty FORCE_COLOR, "0" included, as "force a
            # terminal", which writes bold/italic escapes into redirected output.
            os.environ.pop("FORCE_COLOR", None)
        sync_typer_rendering(no_color=bool(os.getenv("NO_COLOR")))

    def activate(self) -> None:
        """Register this context for nested Typer subcommand resolution."""
        _cli_context.set(self)

    def set_deployment_plan(self, plan: str | None) -> None:
        if plan is not None:
            os.environ["DEPLOYMENT_PLAN"] = plan.upper()


def sync_typer_rendering(*, no_color: bool) -> None:
    """Apply colour preferences to Typer's help and error panels.

    Typer decides ``FORCE_TERMINAL`` once at import, forcing a terminal for any
    non-empty ``FORCE_COLOR`` (``"0"`` included) or under ``GITHUB_ACTIONS``, so
    ``--help`` wrote escapes into pipes even with ``--no-color``.
    """
    from typer import rich_utils

    from opentide.core.logging.config import forced_terminal

    if no_color:
        rich_utils.COLOR_SYSTEM = None
        rich_utils.FORCE_TERMINAL = False
        return
    rich_utils.COLOR_SYSTEM = "auto"
    forced = forced_terminal()
    if forced is None:
        forced = forced_terminal("PY_COLORS")
    if forced is None and os.getenv("GITHUB_ACTIONS"):
        forced = True
    if os.getenv("_TYPER_FORCE_DISABLE_TERMINAL"):
        forced = False
    rich_utils.FORCE_TERMINAL = forced


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
