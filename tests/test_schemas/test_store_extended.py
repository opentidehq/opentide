"""Tests for bundled schema path helpers."""

from __future__ import annotations

from opentide.schemas import store


def test_vocabulary_root_points_at_data() -> None:
    root = store.vocabulary_root()
    assert root.name == "vocabulary"


def test_external_root_points_at_data() -> None:
    root = store.external_root()
    assert root.name == "external"
