"""``verifyRuleText`` answers, read and put back on the block (google-secops-1.0).

``verifyRuleText`` compiles a rule without creating it. It answers ``success:
true`` for a rule that compiles; a refused rule answers HTTP 200 with
``compilationDiagnostics`` and no ``success``. Each diagnostic has a
``message``, a ``severity`` (``ERROR`` or ``WARNING``), an optional ``uri``,
and an optional ``position`` (1-based lines and columns, end inclusive) in the
assembled text, which :meth:`AssembledRule.locate` maps back into the section
key it falls in.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from opentide.platforms.google_secops.compile import AssembledRule, Location


@dataclass(frozen=True)
class Diagnostic:
    """One compilation diagnostic, as Google sent it."""

    message: str
    severity: str
    uri: str | None = None
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True)
class VerifyOutcome:
    """What ``verifyRuleText`` said of one rule."""

    success: bool
    errors: tuple[Diagnostic, ...] = ()
    warnings: tuple[Diagnostic, ...] = ()
    allowed: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.success and not self.errors


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _diagnostic(raw: Mapping[str, Any]) -> Diagnostic:
    position = raw.get("position")
    line = column = None
    if isinstance(position, Mapping):
        line = _int(position.get("startLine"))
        column = _int(position.get("startColumn"))
    uri = raw.get("uri")
    return Diagnostic(
        message=str(raw.get("message") or "no message"),
        severity=str(raw.get("severity") or "ERROR").upper(),
        uri=str(uri) if uri else None,
        line=line,
        column=column,
    )


def read_verify_answer(answer: Mapping[str, Any]) -> VerifyOutcome:
    """A ``VerifyRuleTextResponse`` as a :class:`VerifyOutcome`."""
    raw = answer.get("compilationDiagnostics")
    diagnostics = [_diagnostic(item) for item in raw or [] if isinstance(item, Mapping)]
    allowed = answer.get("allowedRunFrequencies")
    return VerifyOutcome(
        success=answer.get("success") is True,
        errors=tuple(item for item in diagnostics if item.severity != "WARNING"),
        warnings=tuple(item for item in diagnostics if item.severity == "WARNING"),
        allowed=tuple(str(item) for item in allowed or [] if isinstance(item, str)),
    )


def locate(diagnostic: Diagnostic, assembled: AssembledRule) -> Location:
    """The section key, and its own line and column, a diagnostic falls in."""
    return assembled.locate(diagnostic.line, diagnostic.column)


def describe_diagnostic(diagnostic: Diagnostic, assembled: AssembledRule) -> str:
    """One line: where in the block, Google's message, and its documentation link."""
    place = locate(diagnostic, assembled)
    text = f"{place.describe()}: {diagnostic.message}"
    return f"{text} ({diagnostic.uri})" if diagnostic.uri else text
