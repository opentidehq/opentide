"""Operation result types for model delegation methods."""

from __future__ import annotations
from pydantic import BaseModel


class ValidationResult(BaseModel):
    ok: bool
    errors: list[str] = []
    warnings: list[str] = []


class DeploymentResult(BaseModel):
    platform: str
    uuids: list[str]
    dry_run: bool = False
    message: str = ""
