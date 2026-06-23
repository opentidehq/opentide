"""Validation package — headless runtime for CLI, MCP, and future LSP."""

from __future__ import annotations

from typing import Any

from opentide.validation.issues import ValidationIssue, ValidationReport
from opentide.validation.preflight import ObjectRef, PreflightGraph
from opentide.validation.scope import ValidationScope
from opentide.validation.session import run_validation
from opentide.validation.vocab_resolver import RuntimeEnumResolver

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
