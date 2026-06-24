"""Tests for table CSV export."""

from __future__ import annotations

from unittest.mock import patch

import pandas as pd

from opentide.export.table_export import TableEntry, TableExporter


def _setup_opentide_for_table(monkeypatch) -> None:
    from opentide import OpenTide

    threat_uuid = "00000000-0000-4000-8000-000000000010"
    rule_uuid = "00000000-0000-4000-8000-000000000011"
    OpenTide._index = {
        "objects": {
            "threat": {
                threat_uuid: {
                    "name": "Threat One",
                    "metadata": {
                        "uuid": threat_uuid,
                        "tlp": "clear",
                        "version": 1,
                        "created": "2026-01-01",
                        "modified": "2026-01-02",
                    },
                    "threat": {
                        "description": "Threat desc",
                        "att&ck": ["T1059"],
                        "actors": [{"name": "actor::evil-actor #hint"}],
                        "chaining": [{"relation": "follows", "vector": "other"}],
                    },
                }
            },
            "rule": {
                rule_uuid: {
                    "name": "Rule One",
                    "metadata": {
                        "uuid": rule_uuid,
                        "tlp": "amber",
                        "version": 2,
                        "created": "2026-01-03",
                        "modified": "2026-01-04",
                    },
                    "description": "Rule desc",
                }
            },
            "objective": {},
        },
        "configurations": {
            "global": {
                "objects": ["threat", "rule"],
                "exports": {"table": "table.csv"},
            },
            "documentation": {
                "object_names": {"threat": "Threat Vector", "rule": "Detection Rule"},
            },
        },
        "paths": {"tide": {"exports": "/tmp/exports"}},
    }
    OpenTide._initialised = True


def test_rename_columns_capitalises_headers() -> None:
    exporter = TableExporter()
    frame = pd.DataFrame([{"uuid": "u1", "name": "Test", "type": "Rule"}])
    renamed = exporter._rename_columns(frame)
    assert list(renamed.columns) == ["UUID", "Name", "Type"]


def test_flatten_actors_enriches_names(monkeypatch) -> None:
    exporter = TableExporter()
    monkeypatch.setattr(
        "opentide.export.table_export.get_vocab_entry",
        lambda _vocab, actor_id: {"name": "Evil Actor"},
    )
    actors = [{"name": "actor::evil-actor #hint"}]
    assert exporter._flatten_actors(actors) == ["Evil Actor"]


def test_flatten_chaining_groups_by_relation() -> None:
    exporter = TableExporter()
    chains = [
        {"relation": "follows", "vector": "v1"},
        {"relation": "follows", "vector": "v2"},
        {"relation": "precedes", "vector": "v3"},
    ]
    flat = exporter._flatten_chaining(chains)
    assert flat["follows"] == ["v1", "v2"]
    assert flat["precedes"] == ["v3"]


def test_create_entry_threat(monkeypatch) -> None:
    _setup_opentide_for_table(monkeypatch)
    exporter = TableExporter()
    threat_uuid = "00000000-0000-4000-8000-000000000010"
    with (
        patch("opentide.export.table_export.childs", return_value=["child-1"]),
        patch("opentide.export.table_export.parents", return_value=["parent-1"]),
        patch("opentide.export.table_export.get_vocab_entry", return_value={"name": "Evil Actor"}),
    ):
        entry = exporter._create_entry(threat_uuid, "threat")
    assert isinstance(entry, TableEntry)
    assert entry.name == "Threat One"
    assert entry.attack == "T1059"
    assert entry.childs == "child-1"
    assert entry.parents == "parent-1"


def test_create_dataset_skips_missing_index(monkeypatch) -> None:
    _setup_opentide_for_table(monkeypatch)
    exporter = TableExporter()
    exporter.OBJECT_SCOPE = ["threat", "missing_type"]
    with patch.object(
        exporter,
        "_create_entry",
        side_effect=lambda u, t: TableEntry(
            uuid=u,
            name="n",
            type=t,
            tlp="clear",
            description="d",
            version="1",
            created="c",
            modified="m",
            childs="",
            parents="",
            chaining="",
            actors="",
            attack="",
        ),
    ):
        dataset = exporter._create_dataset()
    assert len(dataset) == 1


def test_run_exports_csv(tmp_path, monkeypatch) -> None:
    _setup_opentide_for_table(monkeypatch)
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    exporter = TableExporter()
    exporter.TIDE_EXPORTS_PATH = export_dir
    exporter.EXPORT_PATH = export_dir / "table.csv"
    monkeypatch.setattr(
        exporter,
        "_create_dataset",
        lambda: [
            TableEntry(
                uuid="u1",
                name="Test",
                type="Rule",
                tlp="clear",
                description="desc",
                version="1",
                created="2026-01-01",
                modified="2026-01-02",
                childs="",
                parents="",
                chaining="",
                actors="",
                attack="T1059",
            )
        ],
    )
    exporter.run()
    content = (export_dir / "table.csv").read_text(encoding="utf-8")
    assert "UUID" in content
    assert "Test" in content
