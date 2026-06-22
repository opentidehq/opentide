"""Schema version parsing and migration chain mechanics."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from pydantic import BaseModel, field_validator

MigrationFn = Callable[[Mapping[str, object]], dict[str, object]]


class SchemaVersion(BaseModel):
    """Semantic Tide schema identifier (``family::major.minor``)."""

    family: str
    major: int
    minor: int = 0

    model_config = {"frozen": True}

    @field_validator("family")
    @classmethod
    def _normalise_family(cls, value: str) -> str:
        normalised = value.strip().lower()
        if not normalised:
            raise ValueError("schema family must not be empty")
        return normalised

    @classmethod
    def parse(cls, identifier: str) -> SchemaVersion:
        """Parse identifiers such as ``rule::1.0`` or ``objective::1.0``."""
        if "::" not in identifier:
            raise ValueError(f"invalid schema identifier: {identifier!r}")
        family, version = identifier.split("::", 1)
        return cls.from_version_string(family, version)

    @classmethod
    def from_version_string(cls, family: str, version: str) -> SchemaVersion:
        if "." in version:
            major_text, minor_text = version.split(".", 1)
            return cls(family=family, major=int(major_text), minor=int(minor_text))
        return cls(family=family, major=int(version), minor=0)

    def as_identifier(self) -> str:
        return f"{self.family}::{self.major}.{self.minor}"

    def sort_key(self) -> tuple[str, int, int]:
        return (self.family, self.major, self.minor)


class SchemaVersionChain:
    """Ordered migration chain between schema versions within one family."""

    def __init__(self, family: str) -> None:
        self.family = family.lower()
        self._migrations: dict[tuple[int, int], MigrationFn] = {}

    def register(self, source: SchemaVersion, target: SchemaVersion, fn: MigrationFn) -> None:
        if source.family != self.family or target.family != self.family:
            raise ValueError("migration endpoints must match chain family")
        if source.sort_key() >= target.sort_key():
            raise ValueError("migrations must advance to a higher version")
        self._migrations[(source.major, source.minor)] = fn

    def migrate(
        self, data: Mapping[str, object], source: SchemaVersion, target: SchemaVersion
    ) -> dict[str, object]:
        if source.family != self.family or target.family != self.family:
            raise ValueError("source and target must belong to this chain family")
        if source.sort_key() > target.sort_key():
            raise ValueError("cannot migrate backwards")
        current = dict(data)
        cursor = source
        while cursor.sort_key() < target.sort_key():
            key = (cursor.major, cursor.minor)
            migration = self._migrations.get(key)
            if migration is None:
                raise LookupError(f"no migration registered from {cursor.as_identifier()}")
            current = migration(current)
            cursor = SchemaVersion(family=cursor.family, major=cursor.major, minor=cursor.minor + 1)
            if cursor.sort_key() > target.sort_key():
                cursor = target
        return current

    def path(self, source: SchemaVersion, target: SchemaVersion) -> Sequence[SchemaVersion]:
        if source.sort_key() > target.sort_key():
            raise ValueError("path requires ascending versions")
        versions = [source]
        cursor = source
        while cursor.sort_key() < target.sort_key():
            cursor = SchemaVersion(family=cursor.family, major=cursor.major, minor=cursor.minor + 1)
            if cursor.sort_key() > target.sort_key():
                cursor = target
            versions.append(cursor)
        return versions
