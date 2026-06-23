"""Backward-compatibility shim — delegates to :mod:`opentide.core.files`."""

from __future__ import annotations

import warnings

from opentide.core.files import (
    IndentFullDumper,
    OrderedYAMLDumper,
    resolve_configurations,
    resolve_paths,
    safe_file_name,
)

warnings.warn(
    "Import from 'opentide.core.files' instead of 'Engines.modules.files'",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "IndentFullDumper",
    "OrderedYAMLDumper",
    "resolve_configurations",
    "resolve_paths",
    "safe_file_name",
]
