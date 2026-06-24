"""Tests for core typed structures."""

from __future__ import annotations

from opentide.core.types import IndexSnapshot


def test_index_snapshot_typed_dict_accepts_keys() -> None:
    snapshot: IndexSnapshot = {
        "rules": {"u1": {"name": "Rule"}},
        "files": {"u1": "rule.yaml"},
    }
    assert snapshot["rules"]["u1"]["name"] == "Rule"
