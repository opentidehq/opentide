"""CLI E2E: each command's real document matches the schema ``opentide commands`` publishes.

The schema comes from the ``commands`` document itself, the way an agent
reads it. Every other ``cli_e2e`` test checks its documents against the
result models too (``tests/result_models_support.py``); this one runs each
command over the corpus on purpose, success and failure alike.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import jsonschema
import pytest
from tests.result_models_support import assert_matches_model
from tests.test_cli.e2e.helpers import EVERY_RULE
from typer.testing import CliRunner, Result

from opentide.cli import app

pytestmark = pytest.mark.cli_e2e


@pytest.fixture(scope="module")
def commands_document() -> dict[str, Any]:
    result = CliRunner().invoke(app, ["--json", "commands"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def _schema_for(commands_document: dict[str, Any], path: str) -> dict[str, Any]:
    entries = {entry["path"]: entry for entry in commands_document["commands"]}
    schema = entries[path]["output_schema"]
    assert schema is not None, path
    return {**schema, "$defs": commands_document["$defs"]}


CASES: list[tuple[str, tuple[str, ...]]] = [
    ("validate", ("validate",)),
    ("validate", ("validate", "--check", "schema")),
    ("validate", ("validate", "--strict")),
    ("validate", ("validate", "--type", "bogus")),
    ("validate query", ("validate", "query", "--platform", "sentinel")),
    ("validate query", ("validate", "query", "--platform", "crowdstrike", "--live")),
    ("lint", ("lint",)),
    ("lint", ("lint", "--strict", "--check", "metadata")),
    ("info", ("info",)),
    ("info", ("info", "rules")),
    ("info", ("info", "threats")),
    ("info", ("info", "objectives")),
    ("info", ("info", "coverage", "--technique", "T1059")),
    ("info", ("info", "rulez")),
    ("explain", ("explain",)),
    ("explain", ("explain", "vocab_unknown")),
    ("explain", ("explain", "no_such_code")),
    ("commands", ("commands",)),
    ("rules unreviewed", ("rules", "unreviewed")),
    ("rules unreviewed", ("rules", "unreviewed", "--older-than", "soon")),
    (
        "deploy",
        ("deploy", "--dry-run", "--platform", "sentinel", *EVERY_RULE, "--skip-promotion"),
    ),
    ("deploy", ("deploy", "--dry-run", "--platform", "splunk", *EVERY_RULE, "--skip-promotion")),
    ("deploy", ("deploy", "--dry-run")),
    ("deploy migrate-state", ("deploy", "migrate-state")),
    ("generate exports navigator", ("generate", "exports", "navigator")),
    ("generate", ("generate", "bogus")),
    ("migrate objects", ("migrate", "objects")),
    ("migrate vocab-scope", ("migrate", "vocab-scope")),
    ("share targets", ("share", "targets")),
    ("share preview", ("share", "preview")),
]


@pytest.mark.parametrize(("path", "argv"), CASES, ids=[" ".join(argv) for _, argv in CASES])
def test_document_matches_the_published_schema(
    invoke_cli: Callable[..., Result],
    commands_document: dict[str, Any],
    path: str,
    argv: tuple[str, ...],
) -> None:
    result = invoke_cli(*argv)
    # Not a terminal: one compact line, ending in one newline.
    assert result.stdout.endswith("}\n"), result.stdout[-200:] + result.stderr
    assert result.stdout.count("\n") == 1
    document = json.loads(result.stdout)
    assert document["command"] == path
    jsonschema.validate(document, _schema_for(commands_document, path))
    assert_matches_model(document)


def test_a_document_that_breaks_its_schema_is_caught(
    invoke_cli: Callable[..., Result], commands_document: dict[str, Any]
) -> None:
    document = json.loads(invoke_cli("validate").stdout)
    document["summary"]["objects"] = "nine"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, _schema_for(commands_document, "validate"))
