"""CI sinks: inline annotations and a job summary for the CI provider running opentide.

- GitHub Actions: ``::error file=,line=,col=,title=<code>::<message>`` per
  diagnostic on stdout; the summary is appended to ``$GITHUB_STEP_SUMMARY``.
- GitLab CI: nothing inline (``--format codequality`` is the report GitLab
  shows); the summary is appended to ``opentide-reports/summary.md``.
- Azure Pipelines: ``##vso[task.logissue type=…;…]<message>`` per diagnostic;
  the summary is a file attached with ``##vso[task.uploadsummary]<file>``.

The sinks are additive to the ``human``, ``plain`` and ``agent`` modes and
off in ``json`` and ``mcp``: GitHub and Azure read their commands from
stdout, which belongs to the JSON document or to JSON-RPC there. They are
written with ``sys.stdout.write``, never through Rich, so a command is never
wrapped. See "CI" in ``docs/internal/cli-experience.md``.

Standard library only, like :mod:`opentide.cli.ui.mode`.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Literal, TextIO

from opentide.cli.ui.diagnostics import Diagnostic, relative_path
from opentide.cli.ui.mode import OutputMode, detect_ci, is_machine_mode

CiProvider = Literal["github", "gitlab", "azure"]

#: The providers that have sinks. ``detect_ci`` also answers ``ci`` for another one.
SINK_PROVIDERS: tuple[CiProvider, ...] = ("github", "gitlab", "azure")

#: Where each provider checks the repository out, by the variable that names it.
CHECKOUT_VARIABLES: Mapping[CiProvider, str] = {
    "github": "GITHUB_WORKSPACE",
    "gitlab": "CI_PROJECT_DIR",
    "azure": "BUILD_SOURCESDIRECTORY",
}

#: The directory generated pipelines keep reports in, relative to the checkout.
REPORTS_DIR = "opentide-reports"

#: The GitLab summary file, relative to the checkout. ``setup ci`` uploads it.
GITLAB_SUMMARY = f"{REPORTS_DIR}/summary.md"

_GITHUB_LEVEL = {"error": "error", "warning": "warning", "note": "notice"}

#: Azure has no notice level, so a note gets no inline issue there.
_AZURE_TYPE = {"error": "error", "warning": "warning"}


def ci_provider(env: Mapping[str, str] | None = None) -> CiProvider | None:
    """The CI provider whose sinks apply to this run, or ``None``."""
    provider = detect_ci(env)
    for known in SINK_PROVIDERS:
        if provider == known:
            return known
    return None


def active_provider(
    mode: OutputMode | None = None, env: Mapping[str, str] | None = None
) -> CiProvider | None:
    """:func:`ci_provider`, or ``None`` in the ``json`` and ``mcp`` modes."""
    if is_machine_mode(mode):
        return None
    return ci_provider(env)


def checkout_root(provider: CiProvider | None, env: Mapping[str, str] | None = None) -> Path | None:
    """The directory the provider checked the repository out to, when it says."""
    env = os.environ if env is None else env
    if provider is None:
        return None
    value = env.get(CHECKOUT_VARIABLES[provider], "").strip()
    return Path(value) if value else None


def repository_path(diagnostic: Diagnostic, root: Path | None) -> str | None:
    """The diagnostic's file relative to *root* (the checkout), else its workspace path.

    Annotations and reports name files relative to the repository. The
    workspace usually is the repository; when it is a folder inside it, the
    checkout root keeps the path right.
    """
    if root is not None and diagnostic.file_path is not None:
        shown = relative_path(diagnostic.file_path, root)
        if not Path(shown).is_absolute():
            return shown
    return diagnostic.path


def annotation_text(diagnostic: Diagnostic) -> str:
    """The message, then ``help: …`` on its own line when there is help."""
    if diagnostic.help:
        return f"{diagnostic.message}\nhelp: {diagnostic.help}"
    return diagnostic.message


# --------------------------------------------------------------------------
# GitHub Actions
# --------------------------------------------------------------------------


def github_escape_data(text: str) -> str:
    """Escape a workflow command's message, as ``@actions/core`` does."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def github_escape_property(text: str) -> str:
    """Escape a workflow command property: the message escapes, plus ``:`` and ``,``."""
    return github_escape_data(text).replace(":", "%3A").replace(",", "%2C")


def github_command(level: str, message: str, properties: Iterable[tuple[str, object]] = ()) -> str:
    """``::<level> k=v,…::<message>``, with ``None`` properties left out."""
    rendered = ",".join(
        f"{name}={github_escape_property(str(value))}"
        for name, value in properties
        if value is not None
    )
    head = f"{level} {rendered}" if rendered else level
    return f"::{head}::{github_escape_data(message)}"


def github_annotation(diagnostic: Diagnostic, *, root: Path | None = None) -> str:
    """One diagnostic as a GitHub ``::error``, ``::warning`` or ``::notice`` command.

    GitHub's ``endColumn`` is the last column of the span, one before ours,
    and applies only on a single line, so ``endLine`` repeats ``line``.
    """
    path = repository_path(diagnostic, root)
    line = diagnostic.line if path is not None else None
    column = diagnostic.column if line is not None else None
    end_column = None
    if column is not None and diagnostic.end_column is not None:
        end_column = max(column, diagnostic.end_column - 1)
    return github_command(
        _GITHUB_LEVEL[diagnostic.severity],
        annotation_text(diagnostic),
        (
            ("file", path),
            ("line", line),
            ("endLine", line if end_column is not None else None),
            ("col", column),
            ("endColumn", end_column),
            ("title", diagnostic.code),
        ),
    )


# --------------------------------------------------------------------------
# Azure Pipelines
# --------------------------------------------------------------------------


def azure_escape_data(text: str) -> str:
    """Escape a logging command's message, as ``azure-pipelines-task-lib`` does."""
    return text.replace("%", "%AZP25").replace("\r", "%0D").replace("\n", "%0A")


def azure_escape_property(text: str) -> str:
    """Escape a logging command property: the message escapes, plus ``;`` and ``]``."""
    return azure_escape_data(text).replace(";", "%3B").replace("]", "%5D")


def azure_command(area: str, message: str, properties: Iterable[tuple[str, object]] = ()) -> str:
    """``##vso[<area> k=v;…]<message>``, with ``None`` properties left out."""
    rendered = "".join(
        f"{name}={azure_escape_property(str(value))};"
        for name, value in properties
        if value is not None
    )
    head = f"{area} {rendered}" if rendered else area
    return f"##vso[{head}]{azure_escape_data(message)}"


def azure_annotation(diagnostic: Diagnostic, *, root: Path | None = None) -> str | None:
    """One diagnostic as ``##vso[task.logissue …]``; ``None`` for a note."""
    kind = _AZURE_TYPE.get(diagnostic.severity)
    if kind is None:
        return None
    path = repository_path(diagnostic, root)
    line = diagnostic.line if path is not None else None
    return azure_command(
        "task.logissue",
        annotation_text(diagnostic),
        (
            ("type", kind),
            ("sourcepath", path),
            ("linenumber", line),
            ("columnnumber", diagnostic.column if line is not None else None),
            ("code", diagnostic.code),
        ),
    )


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


def annotation_lines(
    diagnostics: Iterable[Diagnostic],
    provider: CiProvider | None,
    *,
    root: Path | None = None,
) -> list[str]:
    """The inline commands for *provider*; none on GitLab, which reads a report file."""
    lines: list[str] = []
    for diagnostic in diagnostics:
        if provider == "github":
            lines.append(github_annotation(diagnostic, root=root))
        elif provider == "azure" and (line := azure_annotation(diagnostic, root=root)):
            lines.append(line)
    return lines


def _write(lines: Iterable[str], stream: TextIO | None) -> int:
    out = sys.stdout if stream is None else stream
    count = 0
    for line in lines:
        out.write(line + "\n")
        count += 1
    if count:
        out.flush()
    return count


def emit_annotations(
    diagnostics: Iterable[Diagnostic],
    *,
    mode: OutputMode | None = None,
    env: Mapping[str, str] | None = None,
    stream: TextIO | None = None,
) -> int:
    """Write one inline annotation per diagnostic for this run's CI; return how many."""
    provider = active_provider(mode, env)
    root = checkout_root(provider, env)
    return _write(annotation_lines(diagnostics, provider, root=root), stream)


def emit_warning(
    message: str,
    *,
    title: str | None = None,
    mode: OutputMode | None = None,
    env: Mapping[str, str] | None = None,
    stream: TextIO | None = None,
) -> bool:
    """A warning about the whole run, not about a file. Whether one was written."""
    provider = active_provider(mode, env)
    if provider == "github":
        line = github_command("warning", message, (("title", title),))
    elif provider == "azure":
        line = azure_command("task.logissue", message, (("type", "warning"), ("code", title)))
    else:
        return False
    return _write([line], stream) == 1


def summary_file_name(command: str) -> str:
    """``opentide-validate-query.md`` for ``validate query``."""
    slug = "-".join(command.split()) or "run"
    return f"opentide-{slug}.md"


def _azure_summary_path(command: str, env: Mapping[str, str]) -> Path:
    """A new file in the agent's temporary directory, one per command run."""
    directory = Path(env.get("AGENT_TEMPDIRECTORY", "").strip() or tempfile.gettempdir())
    directory.mkdir(parents=True, exist_ok=True)
    stem = Path(summary_file_name(command)).stem
    path, counter = directory / f"{stem}.md", 2
    while path.exists():
        path, counter = directory / f"{stem}-{counter}.md", counter + 1
    return path


def _append(path: Path, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(markdown.rstrip("\n") + "\n\n")


def append_summary(
    markdown: str,
    *,
    command: str,
    mode: OutputMode | None = None,
    env: Mapping[str, str] | None = None,
    stream: TextIO | None = None,
) -> Path | None:
    """Add *markdown* to this run's CI summary; the file written, or ``None``.

    GitHub: appended to ``$GITHUB_STEP_SUMMARY``. GitLab: appended to
    :data:`GITLAB_SUMMARY` in the checkout, which the generated pipeline
    uploads as an artifact. Azure: written to a file of its own and attached
    with ``##vso[task.uploadsummary]``. A summary that cannot be written is
    skipped: it never fails the command.
    """
    env = os.environ if env is None else env
    provider = active_provider(mode, env)
    try:
        if provider == "github":
            target = env.get("GITHUB_STEP_SUMMARY", "").strip()
            if not target:
                return None
            path = Path(target)
            _append(path, markdown)
            return path
        if provider == "gitlab":
            path = (checkout_root(provider, env) or Path.cwd()) / GITLAB_SUMMARY
            _append(path, markdown)
            return path
        if provider == "azure":
            path = _azure_summary_path(command, env)
            _append(path, markdown)
            _write([azure_command("task.uploadsummary", str(path))], stream)
            return path
    except OSError:
        return None
    return None
