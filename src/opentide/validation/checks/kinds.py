"""Validation check identifiers shared by CLI, MCP, and session orchestrator."""

from __future__ import annotations

from enum import Enum


class ValidateCheck(str, Enum):
    """Object validation check types."""

    id_uniqueness = "id-uniqueness"
    uuid_format = "uuid-format"
    schema = "schema"
    cve = "cve"
