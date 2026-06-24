"""Tests for ATT&CK Navigator layer export."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from opentide.export.attack_navigator_layer import (
    AttackNavigatorLayer,
    LayerColor,
    NavigatorLayer,
    TechniqueLayer,
)


def _setup_opentide_index(monkeypatch) -> None:
    from opentide import OpenTide

    threat_uuid = "00000000-0000-4000-8000-000000000001"
    rule_uuid = "00000000-0000-4000-8000-000000000002"
    OpenTide._index = {
        "objects": {
            "threat": {
                threat_uuid: {
                    "name": "Threat A",
                    "metadata": {"uuid": threat_uuid},
                    "threat": {"att&ck": ["T1059"]},
                }
            },
            "rule": {
                rule_uuid: {
                    "name": "Rule B",
                    "metadata": {"uuid": rule_uuid},
                    "detection_model": "parent",
                }
            },
        },
        "configurations": {
            "global": {
                "exports": {"attack_layer": "attack-layer.json"},
                "paths": {"tide": {"exports": "/tmp/exports"}},
            }
        },
        "paths": {"tide": {"exports": "/tmp/exports"}},
    }
    OpenTide._initialised = True


def test_map_objects_and_techniques_threat(monkeypatch) -> None:
    _setup_opentide_index(monkeypatch)
    layer = AttackNavigatorLayer()
    with patch(
        "opentide.export.attack_navigator_layer.techniques_resolver",
        return_value=["T1059"],
    ):
        mapping = layer.map_objects_and_techniques(model_type="threat")
    assert "T1059" in mapping
    assert "[THREAT] Threat A" in mapping["T1059"].objects_names


def test_generate_technique_layer_colors(monkeypatch) -> None:
    _setup_opentide_index(monkeypatch)
    layer = AttackNavigatorLayer()

    def fake_map(model_type: str):
        if model_type == "threat":
            from opentide.export.attack_navigator_layer import TechniqueIndexEntry

            return {
                "T1059": TechniqueIndexEntry(objects_names=["[THREAT] A"], objects_uuids=["u1"]),
                "T1003": TechniqueIndexEntry(objects_names=["[THREAT] B"], objects_uuids=["u2"]),
            }
        from opentide.export.attack_navigator_layer import TechniqueIndexEntry

        return {
            "T1059": TechniqueIndexEntry(objects_names=["[RULE] C"], objects_uuids=["u3"]),
            "T1111": TechniqueIndexEntry(objects_names=["[RULE] D"], objects_uuids=["u4"]),
        }

    monkeypatch.setattr(layer, "map_objects_and_techniques", fake_map)
    techniques = layer.generate_technique_layer()
    colors = {t.techniqueID: t.color for t in techniques}
    assert colors["T1059"] == LayerColor.green
    assert colors["T1003"] == LayerColor.red
    assert colors["T1111"] == LayerColor.blue


def test_assemble_full_layer_includes_legend() -> None:
    layer = AttackNavigatorLayer()
    technique_layer = [
        TechniqueLayer(techniqueID="T1059", color=LayerColor.green, comment="mapped")
    ]
    full = layer.assemble_full_layer(technique_layer)
    assert isinstance(full, NavigatorLayer)
    assert full.techniques == technique_layer
    assert full.legendItems is not None
    assert len(full.legendItems) == 3


def test_export_layer_writes_json(tmp_path: Path, monkeypatch) -> None:
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    layer = AttackNavigatorLayer()
    layer.EXPORT_FILE_PATH = export_dir / "layer.json"
    nav = NavigatorLayer(
        versions={"layer": "4.5"},
        techniques=[TechniqueLayer(techniqueID="T1059", color="#fff", comment="test")],
    )
    layer.export_layer(nav)
    written = json.loads((export_dir / "layer.json").read_text(encoding="utf-8"))
    assert written["techniques"][0]["techniqueID"] == "T1059"


def test_create_layer_orchestrates_pipeline(monkeypatch) -> None:
    layer = AttackNavigatorLayer()
    captured: dict[str, object] = {}

    monkeypatch.setattr(layer, "generate_technique_layer", lambda: [])
    monkeypatch.setattr(
        layer,
        "assemble_full_layer",
        lambda technique_layer: NavigatorLayer(versions={"layer": "4.5"}, techniques=[]),
    )
    monkeypatch.setattr(layer, "export_layer", lambda layer: captured.update({"layer": layer}))
    layer.create_layer()
    assert "layer" in captured
