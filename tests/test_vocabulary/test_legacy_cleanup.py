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
    # 36 before `responders` was retired: it shipped with `keys = []` while
    # `response.responders` was pinned to it, so every authored value failed
    # validation and no instance could fix it. The field is now free text
    # defaulted from `[deployment] default_responders`.
    assert len(toml_files) == 35


def test_responders_is_not_a_bundled_vocabulary() -> None:
    """`responders` is per-organisation configuration, not a vocabulary."""
    vocab_dir = resolve_paths()["vocabularies"]
    assert not (vocab_dir / "responders.vocab.toml").exists()
    assert "responders" not in OpenTide.Vocabularies.Index
