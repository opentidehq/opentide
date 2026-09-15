"""Explorer bundle actor extraction."""

from __future__ import annotations

from datetime import date

from opentide.export.explorer_export import _actors, build_search_documents


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


def test_search_documents_serialize_native_dates() -> None:
    uuid = "00000000-0000-4000-8000-000000000010"
    summaries = [
        {
            "uuid": uuid,
            "type": "threat",
            "name": "Threat",
            "techniques": [],
            "actors": [],
            "platforms": [],
            "status": "",
            "relatedCount": 0,
        }
    ]
    flat_index = {
        uuid: {
            "name": "Threat",
            "metadata": {"created": date(2026, 9, 11), "modified": date(2026, 9, 11)},
        }
    }
    documents = build_search_documents(summaries, flat_index)
    assert "2026-09-11" in documents[0]["content"]
