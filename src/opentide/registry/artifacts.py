"""Versioned framework artifact naming."""

from __future__ import annotations

from opentide.models.version import SchemaVersion


def schema_artifact_name(identifier: str) -> str:
    """Map ``rule::1.0`` → ``rule.1.0.schema.json``."""
    version = SchemaVersion.parse(identifier)
    return f"{version.family}.{version.major}.{version.minor}.schema.json"


def template_artifact_name(identifier: str) -> str:
    """Map ``rule::1.0`` → ``rule.1.0.template.yaml``."""
    version = SchemaVersion.parse(identifier)
    return f"{version.family}.{version.major}.{version.minor}.template.yaml"


def parse_schema_artifact_name(filename: str) -> str:
    """Map ``rule.1.0.schema.json`` → ``rule::1.0``."""
    stem = filename.removesuffix(".schema.json")
    parts = stem.split(".")
    if len(parts) < 3:
        raise ValueError(f"invalid schema artifact filename: {filename!r}")
    family = parts[0]
    major = int(parts[1])
    minor = int(parts[2])
    return SchemaVersion(family=family, major=major, minor=minor).as_identifier()
