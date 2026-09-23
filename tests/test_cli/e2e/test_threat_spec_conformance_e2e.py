"""CLI E2E: the published threat-1.0 conformance fixtures, through ``validate``.

``tests/fixtures/specifications/threat-1.0`` is a verbatim copy of
``fixtures/{valid,invalid}/threat-*.yaml`` from OpenTideHQ/specifications at
``SPEC_COMMIT``. The spec is the contract for the object model (opentide#189):
the valid fixture must pass and every invalid fixture must fail on the field it
was written to break. Refresh the copy when the upstream fixtures change.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from tests.test_cli.conftest import parse_cli_json

pytestmark = pytest.mark.cli_e2e

SPEC_COMMIT = "6897571a373aa2c2241aad1f303de129a0a51df5"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "specifications" / "threat-1.0"
THREATS = Path("Objects") / "Threat Vectors"
# The valid fixture reuses the corpus threat's UUID, which corpus objectives
# reference, so it replaces that file rather than sitting next to it.
CORPUS_THREAT = "threat-0001-simulated-actor.yaml"

INVALID_FIELD = {
    "threat-actor-missing-name.yaml": "threat.actors",
    "threat-actor-unscoped.yaml": "threat.actors",
    "threat-actor-wrong-stage.yaml": "threat.actors",
    "threat-actors-not-list.yaml": "threat.actors",
    "threat-actors-string-list.yaml": "threat.actors",
    "threat-impact-as-string.yaml": "threat.impact",
    "threat-impact-empty.yaml": "threat.impact",
    "threat-impact-semicolon.yaml": "threat.impact",
    "threat-leverage-empty.yaml": "threat.leverage",
    "threat-leverage-high.yaml": "threat.leverage",
    "threat-leverage-semicolon-list-item.yaml": "threat.leverage",
    "threat-leverage-semicolon.yaml": "threat.leverage",
    "threat-missing-body.yaml": "threat",
}


def _validate(invoke_cli, repo: Path, fixture: Path, *, as_name: str) -> tuple[int, dict[str, Any]]:
    target = repo / THREATS / as_name
    shutil.copyfile(fixture, target)
    result = invoke_cli("validate", "--file", as_name)
    return result.exit_code, parse_cli_json(result)


def _errors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [i for i in payload["report"]["issues"] if i["severity"] == "error"]


def test_every_upstream_threat_fixture_has_an_expectation() -> None:
    assert {p.name for p in (FIXTURES / "invalid").glob("*.yaml")} == set(INVALID_FIELD)
    assert [p.name for p in (FIXTURES / "valid").glob("*.yaml")] == ["threat-1.0.yaml"]


def test_valid_threat_fixture_passes(invoke_cli, tide_corpus_repo: Path) -> None:
    exit_code, payload = _validate(
        invoke_cli, tide_corpus_repo, FIXTURES / "valid" / "threat-1.0.yaml", as_name=CORPUS_THREAT
    )
    assert exit_code == 0, payload["report"]["issues"]
    assert payload["report"]["stats"]["objects_checked"] == 1


@pytest.mark.parametrize("name", sorted(INVALID_FIELD))
def test_invalid_threat_fixture_fails_on_its_field(
    invoke_cli, tide_corpus_repo: Path, name: str
) -> None:
    exit_code, payload = _validate(
        invoke_cli, tide_corpus_repo, FIXTURES / "invalid" / name, as_name=name
    )
    assert exit_code != 0, payload
    field = INVALID_FIELD[name]
    paths = [".".join(issue["field_path"]) for issue in _errors(payload)]
    assert any(p == field or p.startswith(f"{field}.") for p in paths), paths


@pytest.mark.parametrize(
    "name",
    [
        "threat-impact-semicolon.yaml",
        "threat-leverage-semicolon.yaml",
        "threat-leverage-semicolon-list-item.yaml",
    ],
)
def test_packed_names_are_one_error_without_a_shorter_suggestion(
    invoke_cli, tide_corpus_repo: Path, name: str
) -> None:
    """The spec forbids collapsing a packed string to one of its names, as a fix or a hint."""
    _, payload = _validate(invoke_cli, tide_corpus_repo, FIXTURES / "invalid" / name, as_name=name)
    errors = _errors(payload)
    assert len(errors) == 1, errors
    assert errors[0]["code"] == "schema_validation"
    assert errors[0]["suggestion"] is None
    assert "as its own item" in errors[0]["message"]
