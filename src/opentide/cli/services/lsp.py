"""``opentide lsp``: the language server for editors, and its diagnostics on the command line."""

from __future__ import annotations

import shlex
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from opentide.cli.ui.contract import ISSUES_FOUND, USAGE_INVALID_VALUE, NextAction
from opentide.cli.ui.diagnostics import relative_path

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

#: What ``lsp start`` prints on stderr when a person runs it at a terminal.
TERMINAL_HINT = (
    "opentide lsp start speaks the language server protocol on stdin and stdout: "
    "your editor starts it (see https://opentide.org/docs/cli/lsp/). Ctrl-C stops it."
)


def serve() -> int:
    """Serve LSP on stdio until the editor exits or closes stdin; return the exit code.

    The server runs on a thread without the GIL, so Ctrl-C still reaches
    Python and stops it (exit 130). Nothing else may write to stdout: the
    output mode for ``lsp start`` is ``mcp``, which keeps it for the protocol.
    """
    from opentide.analysis import EngineUnavailableError, engine

    try:
        engine()
    except EngineUnavailableError as exc:
        # Before any protocol byte, as a line the editor shows in its log.
        print(f"error: {exc}\n  help: {exc.advice}", file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
        return 1
    if sys.stdin.isatty():
        print(TERMINAL_HINT, file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
    _supply_catalogs()
    failure: list[BaseException] = []

    def run() -> None:
        from opentide.analysis import serve_stdio

        try:
            serve_stdio()
        except BaseException as exc:  # reported on the main thread
            failure.append(exc)

    worker = threading.Thread(target=run, name="opentide-lsp", daemon=True)
    worker.start()
    while worker.is_alive():
        worker.join(timeout=0.2)
    if failure:
        print(f"error: the language server stopped: {failure[0]}", file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
        return 1
    return 0


def _supply_catalogs() -> None:
    """Hand the server this opentide's catalogs for the workspace it starts in.

    The server would otherwise read the workspace's committed catalogs at
    ``initialize``, which may come from an older opentide, or fall back to
    the snapshot compiled into the engine. When they cannot be generated, the
    server does as before, and stderr says why.
    """
    from opentide.analysis import engine, own_catalog
    from opentide.registry.discovery import discover_workspace

    try:
        catalogs = own_catalog(discover_workspace())
        module = engine()
        module.set_default_catalog(
            fields=catalogs["fields.json"], deprecations=catalogs["deprecations.json"]
        )
        module.use_host_catalogs()
    except Exception as exc:  # the server still starts, on the workspace's catalogs
        print(  # noqa: T201 -- stderr, outside the protocol
            f"warning: opentide's catalogs could not be generated ({type(exc).__name__}: {exc}); "
            "using the workspace's, or the engine's bundled ones",
            file=sys.stderr,
        )


#: Extensions ``lsp check`` reads in a folder: object files and query files.
CHECKED_SUFFIXES = (".yaml", ".yml", ".kql", ".spl", ".esql", ".eql", ".kuery", ".lucene")


def _expand(paths: Sequence[Path], objects: Sequence[Path]) -> tuple[list[Path], list[str]]:
    """The files *paths* name, and each path that does not exist.

    A file named on the command line is always checked. In a folder, query
    files are checked, and YAML files only when they are objects: CI
    workflows, pre-commit configuration and templates are YAML that no Tide
    schema describes. Hidden files and folders are skipped.
    """
    known = {path.resolve() for path in objects}
    files: list[Path] = []
    missing: list[str] = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                relative = child.relative_to(path).parts
                if any(part.startswith(".") for part in relative) or not child.is_file():
                    continue
                suffix = child.suffix.lower()
                if suffix in (".yaml", ".yml"):
                    if child.resolve() in known:
                        files.append(child)
                elif suffix in CHECKED_SUFFIXES:
                    files.append(child)
        elif path.is_file():
            files.append(path)
        else:
            missing.append(str(path))
    unique: dict[Path, None] = {}
    for item in files:
        unique.setdefault(item.resolve(), None)
    return list(unique), missing


def run_lsp_check(
    ctx: CliContext,
    paths: Sequence[Path],
    *,
    language: str | None = None,
    strict: bool = False,
) -> dict[str, object]:
    """What the language server reports for each file: an object, or a query file.

    Without *paths* every object file of the workspace is checked. The
    workspace's catalogs (``opentide generate schemas``) are used when they
    exist, the bundled ones otherwise. Errors fail the run; warnings fail it
    under *strict*.
    """
    from opentide.analysis import (
        EngineUnavailableError,
        check_file,
        engine,
        engine_versions,
        install_workspace_catalog,
        language_for_path,
        object_files,
        workspace,
    )
    from opentide.cli.services.engine import (
        engine_unavailable_result,
        findings_outcome,
        findings_summary,
    )
    from opentide.cli.ui.diagnostics import diagnostic_from_engine
    from opentide.registry.discovery import discover_workspace

    ctx.apply_environment()
    root = discover_workspace()
    try:
        engine()
        if language is not None and language not in engine().LANGUAGES:
            return {
                "status": "failed",
                "message": f"Unknown language {language!r}",
                "_exit_code": 2,
                "_failure_code": USAGE_INVALID_VALUE,
                "_failure_argument": "--language",
            }
        catalog = install_workspace_catalog(root)
        objects = object_files(root)
        targets, missing = _expand(paths, objects) if paths else (objects, [])
        if missing:
            return {
                "status": "failed",
                "message": f"No such file or folder: {', '.join(missing)}",
                "unmatched": missing,
                "_exit_code": 2,
                "_failure_code": USAGE_INVALID_VALUE,
                "_failure_argument": "PATH",
            }
        unknown = [str(path) for path in targets if (language or language_for_path(path)) is None]
        if unknown:
            return {
                "status": "failed",
                "message": (
                    f"Cannot tell the language of {', '.join(unknown)} from its name; "
                    "pass --language"
                ),
                "_exit_code": 2,
                "_failure_code": USAGE_INVALID_VALUE,
                "_failure_argument": "--language",
            }
        space = workspace(root, objects)
        diagnostics = []
        unreadable: list[str] = []
        for path in targets:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                unreadable.append(f"{relative_path(path, root)}: {exc}")
                continue
            diagnostics.extend(
                diagnostic_from_engine(finding, file_path=path, workspace=root)
                for finding in check_file(space, path, text, language=language)
            )
        versions = engine_versions()
    except EngineUnavailableError as exc:
        return engine_unavailable_result(exc)
    counts = findings_summary(diagnostics)
    checked = len(targets) - len(unreadable)
    summary = {"files": checked, **counts}
    failed = bool(counts["errors"] or (strict and counts["warnings"]) or unreadable)
    files_word = f"{checked} {'file' if checked == 1 else 'files'}"
    outcome_line, outcome_kind = findings_outcome(
        summary, checked=files_word, failed=failed, clean=f"{files_word} clean"
    )
    result: dict[str, object] = {
        "status": "failed" if failed else "passed",
        "message": "Diagnostics found" if failed else f"{files_word} clean",
        "files_checked": checked,
        "diagnostics": [item.to_dict() for item in diagnostics],
        "catalog": catalog.to_dict(),
        "engine": versions,
        "_summary": summary,
        "_diagnostics": diagnostics,
        "_outcome": outcome_line,
    }
    if outcome_kind is not None:
        result["_outcome_kind"] = outcome_kind
    warnings = [f"Could not read {line}" for line in unreadable]
    if catalog.problem:
        used = (
            "the workspace's catalogs" if catalog.source == "workspace" else "the bundled catalogs"
        )
        warnings.append(f"Using {used}: {catalog.problem}; opentide doctor says more")
    if warnings:
        result["warnings"] = warnings
    if not targets:
        del result["_outcome"]
        result.pop("_outcome_kind", None)
        result["status"] = "skipped"
        result["message"] = "No object file to check: the workspace has none yet"
    elif failed:
        ordered = sorted(diagnostics, key=lambda item: item.severity != "error")
        actions = [NextAction(ordered[0].explain, "how to fix it")] if ordered else []
        rerun = ["opentide", "lsp", "check"]
        rerun += ["--language", language] if language else []
        rerun += ["--strict"] if strict else []
        rerun += [str(path) for path in paths]
        actions.append(NextAction(shlex.join(rerun), "check again"))
        result.update({"_exit_code": 1, "_failure_code": ISSUES_FOUND, "_next_actions": actions})
    return result
