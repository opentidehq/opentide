"""Paths to bundled metaschema, definition, and subschema data."""

from __future__ import annotations

from pathlib import Path


def schemas_data_root() -> Path:
    """Root directory for code-first schema assets (replaces Framework/Meta Schemas/)."""
    return Path(__file__).resolve().parent / "data"


def metaschemas_path() -> Path:
    return schemas_data_root()


def subschemas_path() -> Path:
    return schemas_data_root() / "Sub Schemas"


def definitions_path() -> Path:
    return schemas_data_root() / "Definitions"
