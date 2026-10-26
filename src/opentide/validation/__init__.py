"""Validation package — headless runtime for CLI, MCP, and future LSP.

Exports are resolved lazily, like ``opentide.documentation``'s: importing a
light submodule (``opentide.validation.checks.kinds`` for the CLI's
``ValidateCheck``) must not build the session, the registry and the models,
so that loading a command for ``--help`` or completion imports no engine
module.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentide.validation.issues import ValidationIssue, ValidationReport
    from opentide.validation.preflight import ObjectRef, PreflightGraph
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation
    from opentide.validation.vocab_resolver import RuntimeEnumResolver

#: Public name → submodule that defines it.
_EXPORTS = {
    "ObjectRef": "preflight",
    "PreflightGraph": "preflight",
    "RuntimeEnumResolver": "vocab_resolver",
    "ValidationIssue": "issues",
    "ValidationReport": "issues",
    "ValidationScope": "scope",
    "run_validation": "session",
}

__all__ = [
    "ObjectRef",
    "PreflightGraph",
    "RuntimeEnumResolver",
    "ValidationIssue",
    "ValidationReport",
    "ValidationScope",
    "run_validation",
    "validate_all_objects",
    "validate_object",
    "validate_raw_payload",
]


def validate_all_objects(*args: Any, **kwargs: Any) -> Any:
    from opentide.validation import pipeline as pipeline_mod

    return pipeline_mod.validate_all_objects(*args, **kwargs)


def validate_object(*args: Any, **kwargs: Any) -> Any:
    from opentide.validation import pipeline as pipeline_mod

    return pipeline_mod.validate_object(*args, **kwargs)


def validate_raw_payload(*args: Any, **kwargs: Any) -> Any:
    from opentide.validation import pipeline as pipeline_mod

    return pipeline_mod.validate_raw_payload(*args, **kwargs)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_EXPORTS})
