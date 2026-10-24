"""Typed result models, their registry, and how a JSON document is laid out."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest
import typer
from tests.result_models_support import document_problems
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.commands import ROOT_COMMANDS
from opentide.cli.output import document_text, print_document
from opentide.cli.services.introspect import command_tree
from opentide.cli.ui.mode import json_indent
from opentide.cli.ui.results import (
    NO_DOCUMENT,
    PENDING_MODELS,
    RESULT_MODELS,
    CommandError,
    output_schemas,
)

runner = CliRunner()


class _Stream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture(scope="module")
def tree() -> dict[str, Any]:
    return command_tree(typer.main.get_command(app), schemas=False)


def _click_command(path: str) -> Any:
    command: Any = typer.main.get_command(app)
    ctx = typer.Context(command)
    for word in path.split(" "):
        command = command.get_command(ctx, word)
        assert command is not None, f"{path!r} is not a command"
    return command


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def test_every_command_that_runs_has_a_model_or_is_pending(tree: dict[str, Any]) -> None:
    missing = [
        entry["path"]
        for entry in tree["commands"]
        if entry["runs_alone"]
        and entry["path"] not in RESULT_MODELS
        and entry["path"] not in NO_DOCUMENT
        and entry["path"].split(" ")[0] not in PENDING_MODELS
    ]
    assert missing == [], "add a model to RESULT_MODELS, or the root to PENDING_MODELS"


def test_every_root_command_has_a_model_or_is_pending() -> None:
    covered = {path.split(" ")[0] for path in (*RESULT_MODELS, *NO_DOCUMENT)}
    missing = [
        spec.name
        for spec in ROOT_COMMANDS
        if spec.name not in covered and spec.name not in PENDING_MODELS
    ]
    assert missing == []


def test_every_registered_path_is_a_command() -> None:
    for path in (*RESULT_MODELS, *NO_DOCUMENT):
        _click_command(path)


def test_a_pending_command_has_no_model() -> None:
    roots = {path.split(" ")[0] for path in RESULT_MODELS}
    assert roots.isdisjoint(PENDING_MODELS)


def test_every_schema_is_valid_json_schema() -> None:
    import jsonschema

    schemas, defs = output_schemas(sorted(RESULT_MODELS))
    jsonschema.Draft202012Validator.check_schema({"$defs": defs})
    for path, schema in schemas.items():
        assert schema is not None, path
        jsonschema.Draft202012Validator.check_schema({**schema, "$defs": defs})


def test_a_path_with_no_model_has_no_schema() -> None:
    schemas, _ = output_schemas(["mcp", "validate"])
    assert schemas["mcp"] is None
    assert schemas["validate"] == {
        "anyOf": [{"$ref": "#/$defs/ValidateResult"}, {"$ref": "#/$defs/CommandError"}]
    }


# --------------------------------------------------------------------------
# The checks the test suite runs on every E2E document
# --------------------------------------------------------------------------


def _envelope(**payload: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "status": "completed",
        "message": "done",
        **payload,
        "schema_version": 1,
        "command": payload.pop("command", "info"),
        "duration_ms": 1,
        "exit_code": 0,
        "summary": {},
        "next_actions": [],
        "failure": None,
    }


def test_a_key_no_model_names_is_reported() -> None:
    document = _envelope(command="info", version="1.0", surprise=1)
    assert document_problems(document) == ["'info': $.surprise is not in InfoResult"]


def test_a_nested_key_no_model_names_is_reported() -> None:
    platform = {"name": "splunk", "enabled": True, "can_deploy": True, "can_validate": True}
    document = _envelope(command="info", platforms=[{**platform, "colour": "blue"}])
    assert document_problems(document) == ["'info': $.platforms[0].colour is not in InfoResult"]


def test_a_wrong_type_is_reported() -> None:
    (problem,) = document_problems(_envelope(command="info", parse_error_count="three"))
    assert problem.startswith("'info' does not match InfoResult")


def test_a_command_with_no_model_is_reported() -> None:
    assert document_problems(_envelope(command="frobnicate")) == [
        "no result model for 'frobnicate': add it to RESULT_MODELS"
    ]


def test_a_pending_command_needs_only_the_envelope() -> None:
    assert document_problems(_envelope(command="doctor", checks=[{"code": "x"}])) == []


def test_an_error_document_matches_command_error() -> None:
    failure = {
        "code": "usage_invalid_choice",
        "message": "bad",
        "argument": "section",
        "suggestion": "rules",
        "crash_log": None,
    }
    document = {
        **_envelope(command="deploy metadata"),
        "ok": False,
        "status": "failed",
        "error": "bad",
        "exit_code": 2,
        "failure": failure,
    }
    assert document_problems(document) == []
    CommandError.model_validate(document)
    with pytest.raises(ValueError, match="extra"):
        CommandError.model_validate({**document, "records": []})


# --------------------------------------------------------------------------
# Compact and indented JSON
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "tty", "indented"),
    [
        ({}, True, True),
        ({}, False, False),
        ({"OPENTIDE_JSON_INDENT": "0"}, True, False),
        ({"OPENTIDE_JSON_INDENT": "2"}, False, True),
        ({"OPENTIDE_JSON_INDENT": " 2 "}, False, True),
        ({"OPENTIDE_JSON_INDENT": "4"}, False, False),
        ({"OPENTIDE_JSON_INDENT": "yes"}, True, True),
    ],
)
def test_json_is_indented_on_a_tty_unless_the_variable_says(
    env: dict[str, str], tty: bool, indented: bool
) -> None:
    assert json_indent(env=env, stdout=_Stream(tty)) is indented


@pytest.mark.parametrize(("value", "lines"), [("0", 1), ("2", 4)])
def test_a_document_ends_in_exactly_one_newline(
    monkeypatch: pytest.MonkeyPatch, value: str, lines: int
) -> None:
    monkeypatch.setenv("OPENTIDE_JSON_INDENT", value)
    text = document_text({"ok": True, "items": [1]})
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert len(text.splitlines()) == lines
    assert json.loads(text) == {"ok": True, "items": [1]}


def test_print_document_writes_one_line_to_a_pipe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("OPENTIDE_JSON_INDENT", raising=False)
    print_document({"ok": True, "message": "done"})
    assert capsys.readouterr().out == '{"ok":true,"message":"done"}\n'


@pytest.mark.parametrize("value", ["0", "2"])
@pytest.mark.parametrize(
    "argv",
    [["--json", "explain", "vocab_unknown"], ["--json", "info", "rulez"], ["--json", "valdate"]],
    ids=["result", "app-usage-error", "click-usage-error"],
)
def test_every_document_honours_the_variable(argv: list[str], value: str) -> None:
    result = runner.invoke(app, argv, env={"OPENTIDE_JSON_INDENT": value})
    out = result.stdout
    assert out.endswith("\n") and not out.endswith("\n\n"), repr(out[-20:])
    assert (out.count("\n") == 1) is (value == "0")
    assert json.loads(out)["schema_version"] == 1
