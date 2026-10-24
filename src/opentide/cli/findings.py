"""Where results go besides the terminal: a report file and the CI sinks.

``validate`` and ``lint`` call :func:`refuse_report_on_json_stdout` before
they run, :func:`write_report_file` with the diagnostics they built, then
:func:`publish_findings` in the text modes. ``deploy`` and ``validate query``
call :func:`publish_summary`. Under ``--json`` no sink writes anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from opentide.cli.context import CliContext
from opentide.cli.output import CommandResult, emit_usage_error, text_mode
from opentide.cli.ui.ci import (
    active_provider,
    append_summary,
    checkout_root,
    ci_provider,
    emit_annotations,
    repository_path,
)
from opentide.cli.ui.contract import USAGE_INVALID_VALUE
from opentide.cli.ui.diagnostics import Diagnostic
from opentide.cli.ui.render import outcome_kind
from opentide.cli.ui.reports import ReportFormat, build_report
from opentide.cli.ui.summary import diagnostics_summary
from opentide.core.io import dump_json_text

FORMAT_HELP = (
    "text: code frames. sarif: SARIF 2.1.0 for code scanning. codequality: GitLab Code "
    "Quality (Code Climate JSON). A report goes to --output, or to stdout instead of the text"
)
OUTPUT_HELP = "Write the --format report to this file and print the usual text output too"


def refuse_report_on_json_stdout(
    cli: CliContext, report_format: ReportFormat, output: Path | None
) -> None:
    """``--json`` owns stdout, so a report needs ``--output`` there (exit 2)."""
    if cli.json_output and report_format is not ReportFormat.text and output is None:
        emit_usage_error(
            cli,
            f"--format {report_format} with --json needs --output: stdout holds the JSON document",
            argument="--output",
            code=USAGE_INVALID_VALUE,
        )


def _path_for(diagnostic: Diagnostic) -> str | None:
    return repository_path(diagnostic, checkout_root(ci_provider()))


def report_text(
    report_format: ReportFormat, diagnostics: Sequence[Diagnostic], *, command: str
) -> str:
    from opentide._version import __version__

    document = build_report(
        report_format, diagnostics, command=command, version=__version__, path_for=_path_for
    )
    return dump_json_text(document, indent=True, append_newline=False)


def write_report_file(
    report_format: ReportFormat,
    output: Path | None,
    diagnostics: Sequence[Diagnostic],
    *,
    command: str,
) -> Path | None:
    """Write the report to *output*; nothing for ``text`` or without ``--output``."""
    if report_format is ReportFormat.text or output is None:
        return None
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_text(report_format, diagnostics, command=command) + "\n", "utf-8")
    return output


def print_report(
    report_format: ReportFormat,
    diagnostics: Sequence[Diagnostic],
    result: CommandResult,
    *,
    command: str,
) -> NoReturn:
    """The report is the whole of stdout: no code frames, no outcome line, no annotations."""
    print(report_text(report_format, diagnostics, command=command))
    raise SystemExit(result.exit_code)


def publish_summary(cli: CliContext, markdown: str, *, command: str) -> None:
    """Add *markdown* to this run's CI job summary; nothing outside CI or under ``--json``."""
    if cli.json_output:
        return
    append_summary(markdown, command=command, mode=text_mode(cli))


def publish_findings(
    cli: CliContext,
    diagnostics: Sequence[Diagnostic],
    result: CommandResult,
    *,
    command: str,
    outcome: str,
) -> None:
    """Annotations and the job summary for this run's CI, when there is one."""
    mode = text_mode(cli)
    provider = active_provider(mode)
    if provider is None or cli.json_output:
        return
    emit_annotations(diagnostics, mode=mode)
    root = checkout_root(provider)
    paths = {id(item): repository_path(item, root) for item in diagnostics}
    markdown = diagnostics_summary(
        f"opentide {command}",
        outcome,
        diagnostics,
        kind=outcome_kind(result.status, ok=result.ok),
        paths=paths,
    )
    publish_summary(cli, markdown, command=command)
