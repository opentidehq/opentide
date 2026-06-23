"""Bundled vocabulary cleanup invariants."""

from __future__ import annotations

from opentide.core.files import resolve_paths
from opentide.core.registry import OpenTide


def test_removed_orphan_vocab_fields_are_not_indexed() -> None:
    index = OpenTide.Vocabularies.Index
    for field in (
        "indicators",
        "targets",
        "platforms",
        "domains",
        "alert_handling_team",
        "logsources",
        "actions",
        "nist",
        "activities",
        "methods",
        "artifacts",
    ):
        assert field not in index, f"orphan vocab still indexed: {field}"


def test_malapi_vocab_still_indexed() -> None:
    assert "malapi" in OpenTide.Vocabularies.Index


def test_bundled_vocab_file_count() -> None:
    vocab_dir = resolve_paths()["vocabularies"]
    toml_files = list(vocab_dir.glob("*.vocab.toml"))
    assert len(toml_files) == 36
