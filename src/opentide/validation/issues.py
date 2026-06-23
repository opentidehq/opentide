"""Structured validation issue types for CLI, MCP, and future LSP consumers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class ValidationIssue(BaseModel):
    """A single validation finding with stable, machine-readable fields."""

    code: str
    severity: Literal["error", "warning"] = "error"
    object_uuid: str = ""
    object_type: str = ""
    file_path: Path | None = None
    yaml_line: int | None = None
    field_path: tuple[str, ...] = ()
    message: str
    suggestion: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)

    def to_legacy_string(self) -> str:
        """Format compatible with legacy ``list[str]`` error consumers."""
        loc = ".".join(self.field_path) if self.field_path else ""
        if loc:
            return f"{loc}: {self.message}"
        return self.message


class ValidationReport(BaseModel):
    """Aggregate result of a validation session."""

    ok: bool
    issues: list[ValidationIssue] = Field(default_factory=list)
    warnings: list[ValidationIssue] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    def legacy_errors_by_uuid(self) -> dict[str, list[str]]:
        """Map errors to UUID keys for backward-compatible CLI output."""
        grouped: dict[str, list[str]] = {}
        for issue in self.errors:
            key = issue.object_uuid or "_global"
            grouped.setdefault(key, []).append(issue.to_legacy_string())
        return grouped

    def model_dump_json_ready(self) -> dict[str, Any]:
        """JSON-serialisable dict with path fields as strings."""
        payload = self.model_dump(mode="json")
        for bucket in ("issues", "warnings"):
            for item in payload.get(bucket, []):
                if item.get("field_path"):
                    item["field_path"] = list(item["field_path"])
        return payload
