"""SchemaVersion and SchemaVersionChain."""

from __future__ import annotations

from opentide.models.version import SchemaVersion, SchemaVersionChain


def test_schema_version_parse() -> None:
    version = SchemaVersion.parse("rule::1.0")
    assert version.family == "rule"
    assert version.major == 1
    assert version.minor == 0
    assert version.as_identifier() == "rule::1.0"


def test_schema_version_from_version_string_minor() -> None:
    version = SchemaVersion.from_version_string("objective", "2.3")
    assert version.major == 2
    assert version.minor == 3
    assert version.as_identifier() == "objective::2.3"


def test_schema_version_sort_key() -> None:
    left = SchemaVersion.parse("rule::1.0")
    right = SchemaVersion.parse("rule::1.1")
    assert left.sort_key() < right.sort_key()


def test_schema_version_chain_migrate() -> None:
    chain = SchemaVersionChain("rule")

    def bump(data: dict[str, object]) -> dict[str, object]:
        copy = dict(data)
        copy["version"] = 2
        return copy

    source = SchemaVersion.parse("rule::1.0")
    target = SchemaVersion.parse("rule::1.1")
    chain.register(source, target, bump)
    result = chain.migrate({"version": 1}, source, target)
    assert result["version"] == 2


def test_schema_version_chain_path() -> None:
    chain = SchemaVersionChain("rule")
    source = SchemaVersion.parse("rule::1.0")
    target = SchemaVersion.parse("rule::1.2")
    path = chain.path(source, target)
    assert path[0].as_identifier() == "rule::1.0"
    assert path[-1].as_identifier() == "rule::1.2"
