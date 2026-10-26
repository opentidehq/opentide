"""Presentation for the opentide CLI: the output contract in code.

``mode``         who is reading (``human``, ``plain``, ``agent``, ``json``, ``mcp``)
``glyphs``       status glyphs by name, with ASCII fallbacks
``contract``     ``Failure``, ``NextAction``, usage-error codes, ``did_you_mean``
``render``       outcome, warning, error and next-step lines
``crash``        ``error[internal]``, the redacted crash log and the issue link
``diagnostics``  ``Diagnostic``, ``Fix``, ``TextEdit``, adapters from validation and lint findings
``codeframe``    ``render_diagnostics``: diagnostics as code frames

``docs/internal/cli-experience.md`` is the specification. Submodules load on
first use, so asking for the mode never loads Rich: ``from opentide.cli.ui
import Diagnostic`` imports ``diagnostics`` only.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentide.cli.ui.codeframe import render_diagnostics
    from opentide.cli.ui.diagnostics import (
        Diagnostic,
        Fix,
        SourceFiles,
        TextEdit,
        annotate,
        diagnostic_from_issue,
        diagnostic_from_lint_finding,
        diagnostics_from_issues,
    )

#: Public name → submodule that defines it.
_EXPORTS = {
    "Diagnostic": "diagnostics",
    "Fix": "diagnostics",
    "TextEdit": "diagnostics",
    "SourceFiles": "diagnostics",
    "annotate": "diagnostics",
    "diagnostic_from_issue": "diagnostics",
    "diagnostics_from_issues": "diagnostics",
    "diagnostic_from_lint_finding": "diagnostics",
    "render_diagnostics": "codeframe",
}

__all__ = [
    "Diagnostic",
    "Fix",
    "SourceFiles",
    "TextEdit",
    "annotate",
    "diagnostic_from_issue",
    "diagnostic_from_lint_finding",
    "diagnostics_from_issues",
    "render_diagnostics",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(f"{__name__}.{module}"), name)


def __dir__() -> list[str]:
    return sorted({*globals(), *_EXPORTS})
