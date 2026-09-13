"""Explorer bundle actor extraction."""

from __future__ import annotations

from opentide.export.explorer_export import _actors


def test_actors_extracts_object_names() -> None:
    body = {
        "metadata": {"schema": "threat::1.0"},
        "threat": {"actors": [{"name": "att&ck::G0006", "sighting": "lab"}]},
    }
    assert _actors(body, "threat") == ["att&ck::G0006"]


def test_actors_skips_string_leftovers() -> None:
    body = {"threat": {"actors": ["G0006", {"name": "att&ck::G0006"}]}}
    assert _actors(body, "threat") == ["att&ck::G0006"]


def test_actors_empty_for_non_threats() -> None:
    assert _actors({"threat": {"actors": [{"name": "att&ck::G0006"}]}}, "rule") == []
