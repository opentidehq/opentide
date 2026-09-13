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


def test_run_generate_exports_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    attack = MagicMock()
    table = MagicMock(run=MagicMock())
    revisions = MagicMock()
    monkeypatch.setattr("opentide.export.attack_navigator_layer.run", attack)
    monkeypatch.setattr("opentide.export.table_export.TableExporter", lambda: table)
    monkeypatch.setattr("opentide.export.revisions_export.run", revisions)
    generation.run_generate_phase(GeneratePhase.exports)
    attack.assert_called_once()
    table.run.assert_called_once()
    revisions.assert_called_once()


def test_run_generate_snippets_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    generate = MagicMock()
    monkeypatch.setattr("opentide.generation.vscode_snippets.run", generate)
    generation.run_generate_phase(GeneratePhase.snippets)
    generate.assert_called_once()


def test_run_generate_docs_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    run_docs = MagicMock()
    monkeypatch.setattr("opentide.documentation.cli.run", run_docs)
    generation.run_generate_phase(GeneratePhase.docs)
    run_docs.assert_called_once()


def test_run_generate_all_runs_every_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    def _record(phase: str) -> None:
        called.append(phase)

    monkeypatch.setattr(generation, "run_generate_phase", _record)
    generation.run_generate_all()
    assert called == list(generation._PHASE_ORDER)


def test_run_generate_single_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = MagicMock()
    monkeypatch.setattr(generation, "run_generate_phase", MagicMock())
    result = generation.run_generate(ctx, phase="schemas")
    assert result["phase"] == "schemas"


def test_run_generate_full_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = MagicMock()
    monkeypatch.setattr(generation, "run_generate_all", MagicMock())
    result = generation.run_generate(ctx)
    assert "phases" in result


def test_run_generate_docs_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    run_docs = MagicMock()
    monkeypatch.setattr("opentide.documentation.cli.run", run_docs)
    generation.run_generate_docs(rules=True)
    run_docs.assert_called_once()
