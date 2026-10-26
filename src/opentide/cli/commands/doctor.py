"""``opentide doctor``: one checklist for the installation, the workspace and its integrations."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import CommandResult, emit_result


def doctor_cmd(
    ctx: typer.Context,
    offline: bool = typer.Option(
        False, "--offline", help="Skip the network checks (PyPI release, proxy reachability)"
    ),
) -> None:
    """Check the installation, the workspace and its integrations.

    Each check prints a status, what it found and, when something needs doing,
    the command that fixes it. Credentials are reported as set or unset, never
    printed. Exits 1 when any check fails; warnings alone exit 0.
    """
    cli = get_context(ctx)
    cli.apply_environment()
    from opentide.cli.services.doctor import DoctorContext, render_checks, run_doctor
    from opentide.core.logging.config import get_stdout_console
    from opentide.core.root import find_workspace_root

    workspace = cli.repo.resolve()
    # --repo and OPENTIDE_REPO_ROOT both land in cli.repo; discovery is what
    # the walk up from the current directory finds.
    explicit = cli.repo_explicit or workspace != find_workspace_root().resolve()
    payload = run_doctor(
        DoctorContext(workspace=workspace, workspace_explicit=explicit, offline=offline)
    )
    if not cli.json_output and not cli.quiet:
        render_checks(get_stdout_console(), payload["checks"])
    emit_result(cli, CommandResult.from_payload(payload))
