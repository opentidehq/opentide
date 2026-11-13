"""The analysis engine: offline query checks and highlighting, in process.

The engine is Rust, compiled into this package as ``opentide._native``
(``bindings/python/``, built by ``hatch_build.py``): ``pip install opentide`` is
the one install. :func:`engine` loads it, and a damaged install fails there, with
one message (:class:`EngineUnavailableError`). A missing engine is an error,
never a skipped check. The workspace's checks are :class:`opentide.Workspace`'s
(``validate``, ``lint``); this module checks one query on its own.

Positions are the CLI's: 1-based lines and columns, columns in code points,
``end_column`` exclusive.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from opentide._native import Diagnostic as EngineDiagnostic

#: ``failure.code`` (and ``opentide explain`` page) when the engine does not import.
ENGINE_UNAVAILABLE = "engine_unavailable"
REINSTALL_COMMAND = "pip install --force-reinstall opentide"

Severity = Literal["error", "warning", "note"]
_SEVERITIES: dict[str, Severity] = {
    "error": "error",
    "warning": "warning",
    "information": "note",
    "hint": "note",
}


class EngineUnavailableError(RuntimeError):
    """The compiled engine does not import: the installation is damaged."""

    code = ENGINE_UNAVAILABLE

    def __init__(self, cause: str) -> None:
        super().__init__(f"The opentide analysis engine does not load: {cause}")
        self.cause = cause

    @property
    def advice(self) -> str:
        return f"reinstall opentide: {REINSTALL_COMMAND}"


@cache
def engine() -> ModuleType:
    """The ``opentide._native`` module. Raises :class:`EngineUnavailableError`."""
    import importlib

    try:
        # Through the import system, not the package attribute, so a module
        # that fails to load (or is hidden in tests) is reported every time.
        return importlib.import_module("opentide._native")
    except ImportError as exc:
        raise EngineUnavailableError(str(exc) or type(exc).__name__) from exc


def engine_versions() -> dict[str, str]:
    """``{"engine": …}``: the version of the language-server crates compiled in."""
    return {"engine": str(engine().ENGINE_VERSION)}


#: Engine sentences that promise a step opentide does not offer, and what opentide
#: says instead: ``(code, engine text, replacement)``. language-server 0.8.0 asks to
#: "declare" an SPL command an app provides, and no configuration declares one.
_MESSAGE_CORRECTIONS: tuple[tuple[str, str, str], ...] = (
    (
        "spl_unknown_command",
        "; if an app on the search head provides it, declare it",
        "; an app on the search head may provide it (opentide cannot declare app commands yet)",
    ),
)


def _corrected_message(code: str, message: str) -> str:
    """*message*, without a promise of a setting opentide does not have."""
    for wanted, engine_text, replacement in _MESSAGE_CORRECTIONS:
        if code == wanted and message.endswith(engine_text):
            return message.removesuffix(engine_text) + replacement
    return message


def _span_end(
    line: int, column: int, end_line: int, end_column: int, text: str | None
) -> tuple[int, int]:
    """The end of a span on the line of its last character.

    The engine's end is exclusive, so a span whose last character is a line's
    newline (an "unexpected end" after ``| where (``) ends at column 1 of the
    next line. That line holds none of the span: it ends on the line before,
    after that line's last character. One place, so validate, lint, MCP,
    SARIF and GitHub annotations all agree.
    """
    if end_column != 1 or end_line <= line:
        return end_line, end_column
    last = end_line - 1
    # Lines as the engine counts them: split on LF, a CR before it not counted.
    lines = text.split("\n") if text is not None else None
    if lines is not None and 0 < last <= len(lines):
        length = len(lines[last - 1].removesuffix("\r"))
        return last, max(length + 1, column + 1) if last == line else length + 1
    if last == line:
        return line, column + 1
    return end_line, end_column


@dataclass(frozen=True)
class Finding:
    """One engine diagnostic, in the CLI's coordinates."""

    code: str
    severity: Severity
    message: str
    line: int
    column: int
    end_line: int
    end_column: int
    field_path: tuple[str, ...] = ()
    suggestion: str | None = None

    @classmethod
    def from_engine(cls, diagnostic: EngineDiagnostic, text: str | None = None) -> Finding:
        """*diagnostic* in the CLI's coordinates; *text* is what its positions count in."""
        end_line, end_column = _span_end(
            diagnostic.line, diagnostic.column, diagnostic.end_line, diagnostic.end_column, text
        )
        return cls(
            code=diagnostic.code,
            severity=_SEVERITIES.get(diagnostic.severity, "note"),
            message=_corrected_message(diagnostic.code, diagnostic.message),
            line=diagnostic.line,
            column=diagnostic.column,
            end_line=end_line,
            end_column=end_column,
            field_path=tuple(diagnostic.field_path or ()),
            suggestion=diagnostic.suggestion,
        )

    @property
    def single_line_end(self) -> int:
        """``end_column`` on the finding's first line (a frame underlines one line)."""
        if self.end_line == self.line:
            return self.end_column
        return self.column + 1


def check_query(
    text: str, *, language: str, platform: str | None = None, stack: str | None = None
) -> list[Finding]:
    """One query on its own, in its own coordinates."""
    return [
        Finding.from_engine(item, text)
        for item in engine().analyze_query(text, language, platform=platform, stack=stack)
    ]


@dataclass(frozen=True)
class HighlightToken:
    """One highlighted span, as the editor colours it."""

    line: int
    column: int
    end_line: int
    end_column: int
    #: A HighlightSpec capture: ``keyword``, ``function``, ``string``, ...
    capture: str


def highlight(text: str, language: str) -> list[HighlightToken]:
    """The tokens the language server colours in *text*; queries in an object included."""
    return [HighlightToken(*token) for token in engine().highlight(text, language)]


def language_for_path(path: Path | str) -> str | None:
    """``opentide-yaml`` for an object file, a query language for its extension, else ``None``."""
    return engine().language_for_path(str(path))


def describe(code: str) -> str | None:
    """The engine's sentence for *code*, or ``None`` (also when the engine does not load)."""
    try:
        module = engine()
    except EngineUnavailableError:
        return None
    return module.describe_code(code)


def engine_codes() -> Sequence[str]:
    """Every code the engine emits; empty when the engine does not load."""
    try:
        return tuple(engine().CODES)
    except EngineUnavailableError:
        return ()
