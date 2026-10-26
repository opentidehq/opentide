"""``opentide info vocab``: a vocabulary's contract revisions, pins and stages (#523)."""

from __future__ import annotations

import json
from io import StringIO
from typing import Any
from unittest.mock import patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.context import CliContext
from opentide.cli.services import info as info_service
from opentide.generation.vocabulary import VocabularyDefinition, parse_vocabulary_document

runner = CliRunner()


def _definition() -> VocabularyDefinition:
    """A staged vocabulary whose lifecycle defines 1.0, 1.1 and 2.0."""
    return parse_vocabulary_document(
        {
            "name": "Demo Surface",
            "field": "demo",
            "key": "name",
            "stages": [{"id": "OS", "name": "Operating Systems"}, {"id": "Cloud"}],
            "keys": [
                {"name": "Windows", "version": "1.0", "tide.vocab.stages": "OS"},
                {"name": "Linux", "version": "1.0", "tide.vocab.stages": "OS"},
                {"name": "Legacy", "version": "1.0", "removed": "2.0"},
                {"name": "AWS", "version": "1.1", "tide.vocab.stages": "Cloud"},
            ],
        },
        source="demo.vocab.toml",
    )


def test_revisions_count_introduced_removed_and_admitted_keys() -> None:
    assert info_service._vocab_revisions(_definition()) == [
        {"revision": "1.0", "introduced": 3, "removed": 0, "admitted": 3},
        {"revision": "1.1", "introduced": 1, "removed": 0, "admitted": 4},
        {"revision": "2.0", "introduced": 0, "removed": 1, "admitted": 3},
    ]


def test_detail_reports_pins_from_the_pin_manifests() -> None:
    pins = {
        "threat::1.0": {"threat.surface": "demo::1.0", "threat.severity": "severity::1.0"},
        "threat::9.9": {"threat.surface": "demo::1.5"},
    }
    with patch("opentide.models.vocab_pins.all_pins", return_value=pins):
        detail = info_service._vocab_detail("demo", _definition())

    assert detail["entries"] == 4
    assert detail["removed"] == 1
    assert detail["latest_revision"] == "2.0"
    assert detail["staged"] is True
    assert detail["stages"] == ["OS", "Cloud"]
    assert detail["key"] == "name"
    assert detail["pins"] == [
        {
            "schema": "threat::1.0",
            "field": "threat.surface",
            "revision": "1.0",
            "defined": True,
            "admitted": 3,
            "scoped": True,
        },
        {
            # No model registered for threat::9.9: the latest threat model stands in.
            "schema": "threat::9.9",
            "field": "threat.surface",
            "revision": "1.5",
            "defined": False,
            "admitted": 4,
            "scoped": True,
        },
    ]


def test_unstaged_vocabulary_without_lifecycle_defaults_to_one_revision() -> None:
    definition = parse_vocabulary_document(
        {"name": "Flat", "field": "flat", "keys": [{"name": "a"}, {"name": "b"}]}
    )
    overview = info_service._vocab_overview("flat", definition)
    assert overview == {
        "name": "flat",
        "title": "Flat",
        "entries": 2,
        "removed": 0,
        "latest_revision": "1.0",
        "staged": False,
    }


@pytest.mark.parametrize(
    ("schema_id", "path", "scoped"),
    [
        ("threat::1.0", "threat.surface", True),
        ("threat::1.0", "threat.actors.name", True),
        ("threat::1.0", "threat.severity", False),
        ("threat::1.0", "metadata.tlp", False),
        ("objective::1.0", "objective.signals.entities", True),
        # objective::1.1 is pinned but has no model; objective::1.0 stands in.
        ("objective::1.1", "objective.signals.entities", True),
        ("rule::1.1", "techniques", False),
        ("threat::1.0", "threat.nowhere", None),
        ("threat::1.0", "threat.severity.deeper", None),
        ("nofamily::1.0", "x", None),
    ],
)
def test_field_is_scoped_reads_the_model_declaration(
    schema_id: str, path: str, scoped: bool | None
) -> None:
    assert info_service._field_is_scoped(schema_id, path) is scoped


def _collect(vocab: str | None) -> dict[str, Any]:
    with patch.object(info_service, "Opentide") as mock_ot:
        mock_ot.Platforms.items.return_value = []
        mock_ot.Models.rules = {}
        mock_ot.Models.threats = {}
        mock_ot.Models.objectives = {}
        mock_ot.Vocabularies.Index = {"demo": _definition(), "rule": _definition()}
        mock_ot.Configuration.Global.objects = ["rule"]
        return info_service.collect_info(CliContext(json_output=True), section="vocab", vocab=vocab)


def test_collect_info_lists_file_vocabularies_without_object_vocabularies() -> None:
    payload = _collect(None)
    assert [item["name"] for item in payload["vocabularies"]] == ["demo"]


def test_collect_info_unknown_vocabulary_names_the_available_ones() -> None:
    with pytest.raises(info_service.UnknownVocabularyError) as excinfo:
        _collect("rule")
    assert excinfo.value.available == ["demo"]
    assert str(excinfo.value) == "Unknown vocabulary: rule. Available: demo"


def _render(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> str:
    buffer = StringIO()
    console = Console(file=buffer, width=200, force_terminal=False, no_color=True)
    monkeypatch.setattr(info_service, "get_stdout_console", lambda: console)
    info_service.render_info(payload, section="vocab")
    return buffer.getvalue()


def test_render_vocab_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    pins = {"threat::1.0": {"threat.surface": "demo::1.5"}}
    with patch("opentide.models.vocab_pins.all_pins", return_value=pins):
        detail = info_service._vocab_detail("demo", _definition())
    output = _render(monkeypatch, {"vocabulary": detail})
    assert "Vocabulary demo" in output
    assert "OS, Cloud" in output
    assert "1.5 (undefined)" in output
    row = next(line for line in output.splitlines() if "threat.surface" in line)
    assert "yes" in row


def test_render_vocab_detail_without_pins_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    with patch("opentide.models.vocab_pins.all_pins", return_value={}):
        detail = info_service._vocab_detail("demo", _definition())
    assert "No object schema pins this vocabulary" in _render(monkeypatch, {"vocabulary": detail})


def test_render_vocab_list(monkeypatch: pytest.MonkeyPatch) -> None:
    overview = info_service._vocab_overview("demo", _definition())
    output = _render(monkeypatch, {"vocabularies": [overview]})
    assert "Vocabularies (1)" in output
    row = next(line for line in output.splitlines() if "demo" in line)
    assert "2.0" in row


def test_cli_info_vocab_surface_json() -> None:
    result = runner.invoke(app, ["--json", "info", "vocab", "surface"])
    assert result.exit_code == 0, result.stdout
    vocab = json.loads(result.stdout)["vocabulary"]
    assert vocab["name"] == "surface"
    assert vocab["staged"] is True
    assert "Protocol" in vocab["stages"]
    assert vocab["entries"] == sum(item["introduced"] for item in vocab["revisions"])
    pin = next(pin for pin in vocab["pins"] if pin["field"] == "threat.surface")
    assert pin["scoped"] is True
    assert pin["defined"] is True


def test_cli_info_vocab_human_output() -> None:
    result = runner.invoke(app, ["info", "vocab", "surface"])
    assert result.exit_code == 0
    assert "Vocabulary surface" in result.stdout
    assert "threat.surface" in result.stdout


def test_cli_info_vocab_lists_vocabularies() -> None:
    result = runner.invoke(app, ["--json", "info", "vocab"])
    assert result.exit_code == 0
    names = [item["name"] for item in json.loads(result.stdout)["vocabularies"]]
    assert "surface" in names
    assert "rule" not in names


def test_cli_info_vocab_unknown_name_lists_available() -> None:
    result = runner.invoke(app, ["--json", "info", "vocab", "nope"])
    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert body["ok"] is False
    assert body["message"].startswith("Unknown vocabulary: nope. Available: ")
    assert "surface" in body["message"]


def test_cli_info_name_only_with_vocab_section() -> None:
    result = runner.invoke(app, ["--json", "info", "rules", "surface"])
    assert result.exit_code == 1
    assert "Only the vocab section takes a name" in result.stdout


def _malformed_definition() -> VocabularyDefinition:
    return parse_vocabulary_document(
        {
            "name": "Broken",
            "field": "broken",
            "keys": [{"name": "a", "version": "1.0"}, {"name": "b", "version": "next"}],
        }
    )


@pytest.mark.parametrize("vocab", [None, "broken"])
def test_collect_info_malformed_lifecycle_version_names_the_key(vocab: str | None) -> None:
    with patch.object(info_service, "Opentide") as mock_ot:
        mock_ot.Platforms.items.return_value = []
        mock_ot.Models.rules = {}
        mock_ot.Models.threats = {}
        mock_ot.Models.objectives = {}
        mock_ot.Vocabularies.Index = {"broken": _malformed_definition()}
        mock_ot.Configuration.Global.objects = []
        with pytest.raises(info_service.InvalidVocabularyLifecycleError) as excinfo:
            info_service.collect_info(CliContext(json_output=True), section="vocab", vocab=vocab)
    assert str(excinfo.value) == (
        "Vocabulary broken: key 'b' has an invalid version 'next' (expected M or M.m)"
    )


def test_cli_info_vocab_malformed_lifecycle_version_emits_json_error() -> None:
    with patch.object(
        info_service, "_file_vocabularies", return_value={"broken": _malformed_definition()}
    ):
        result = runner.invoke(app, ["--json", "info", "vocab"])
    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert body["ok"] is False
    assert body["message"].startswith("Vocabulary broken: key 'b' has an invalid version")
