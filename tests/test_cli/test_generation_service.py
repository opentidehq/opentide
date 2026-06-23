"""CLI generation service smoke tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opentide.cli.enums import GeneratePhase
from opentide.cli.services import generation


def test_run_generate_object_vocab_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    called = MagicMock()
    monkeypatch.setattr("opentide.indexing.object_vocab.run", called)
    generation.run_generate_phase(GeneratePhase.object_vocab)
    called.assert_called_once()


def test_run_generate_unknown_phase() -> None:
    with pytest.raises(ValueError, match="Unknown generation phase"):
        generation.run_generate_phase("not-a-phase")  # type: ignore[arg-type]


def test_run_generate_templates_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    generate = MagicMock()
    reload = MagicMock()
    monkeypatch.setattr("opentide.generation.template.run", generate)
    monkeypatch.setattr(generation.IndexManager, "reload", reload)
    monkeypatch.setattr(generation.OpenTide, "reload", MagicMock())
    generation.run_generate_phase(GeneratePhase.templates)
    generate.assert_called_once()
    reload.assert_called_once()


def test_run_generate_schemas_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    generate = MagicMock()
    monkeypatch.setattr("opentide.generation.schema.run", generate)
    generation.run_generate_phase(GeneratePhase.schemas)
    generate.assert_called_once()


def test_run_generate_playbook_map_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    generate = MagicMock()
    monkeypatch.setattr("opentide.export.playbook_map.run", generate)
    generation.run_generate_phase(GeneratePhase.playbook_map)
    generate.assert_called_once()


def test_run_generate_exports_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    attack = MagicMock()
    table = MagicMock(run=MagicMock())
    monkeypatch.setattr("opentide.export.attack_navigator_layer.run", attack)
    monkeypatch.setattr("opentide.export.table_export.TableExporter", lambda: table)
    generation.run_generate_phase(GeneratePhase.exports)
    attack.assert_called_once()
    table.run.assert_called_once()
