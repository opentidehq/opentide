"""``generate`` fails by phase, names the object, and prints one JSON document (#579).

The 0.13.0 report found three ways a broken corpus got past ``generate``: a
phase logged an error and the run exited ``0`` (A9), ``generate exports``
reported a ``KeyError`` as the bare key (A10b), and ``generate docs`` let the
exception escape as a traceback instead of the ``--json`` result (A11).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from tests.test_cli.e2e.helpers import write_tutorial_objects
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
from opentide.generation.errors import (
    GenerationPhaseError,
    ObjectGenerationError,
    describe_exception,
    failing_phase,
    rendering,
)

runner = CliRunner()

_THREAT = "00000000-0000-4000-8001-000000000001"
_RULE = "00000000-0000-4000-8003-000000000001"

# Unset so `generate` never mistakes the test runner's own CI for this repo's.
_CI_ENV = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "DEPLOYMENT_PLAN")


def _tutorial(tmp_path: Path) -> Path:
    repo = tmp_path / "detections"
    run_repo_setup(RepoSetupOptions(path=repo, name="Detections", yes=True))
    write_tutorial_objects(repo)
    return repo


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{path.name} no longer contains {old!r}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _invoke(repo: Path, *args: str) -> Result:
    env = dict.fromkeys(_CI_ENV)
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    return runner.invoke(app, ["--json", "--repo", str(repo), *args], env=env)


def _failure(result: Result) -> dict[str, object]:
    """The one result document a failed run must print, and nothing else."""
    rendered = result.stdout + result.stderr
    assert result.exit_code == 1, rendered
    assert "Traceback" not in rendered
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["status"] == "failed"
    return payload


@pytest.fixture
def no_attack_threat(tmp_path: Path) -> Path:
    repo = _tutorial(tmp_path)
    _edit(
        repo / "objects" / "threats" / "simulated-actor.yaml",
        "  mitre_attack:\n    - T1059\n",
        "",
    )
    return repo


@pytest.mark.parametrize("command", [("generate", "exports"), ("generate", "exports", "objects")])
def test_an_export_failure_names_the_phase_type_and_object(
    no_attack_threat: Path, command: tuple[str, ...]
) -> None:
    """A10(b): the message was `'mitre_attack'`, and `exports objects` a traceback."""
    payload = _failure(_invoke(no_attack_threat, *command))
    assert payload["phase"] == "exports"
    assert payload["message"] == f"exports: KeyError: 'mitre_attack' while rendering {_THREAT}"


def test_an_explorer_failure_names_the_object(no_attack_threat: Path) -> None:
    payload = _failure(_invoke(no_attack_threat, "generate", "explorer"))
    assert payload["phase"] == "explorer"
    assert payload["message"] == f"explorer: KeyError: 'mitre_attack' while rendering {_THREAT}"


# `docs index` fails on the rule's relation count, through `run_document`.
@pytest.mark.parametrize(
    "command", [("generate", "docs"), ("generate",), ("generate", "docs", "index")]
)
def test_a_docs_failure_is_one_result_naming_the_phase(
    tmp_path: Path, command: tuple[str, ...]
) -> None:
    """A11: `generate docs` raised a traceback where `--json` promises a document."""
    repo = _tutorial(tmp_path)
    missing = "00000000-0000-4000-8002-DEADBEEF0000"
    _edit(
        repo / "objects" / "rules" / "sentinel-kql-rule.yaml",
        "detection_model: 00000000-0000-4000-8002-000000000001",
        f"detection_model: {missing}",
    )
    payload = _failure(_invoke(repo, *command))
    assert payload["phase"] == "docs"
    assert payload["message"] == (
        f"docs: Exception: detection_model {missing} does not exist in the catalogue "
        f"while rendering {_RULE}"
    )


@pytest.mark.parametrize(
    ("command", "phase"),
    [
        (("generate",), "docs"),
        # `schemas` reloads the registry, which logs the same error again.
        (("generate", "schemas", "templates", "vocabs", "snippets"), "schemas"),
    ],
)
def test_a_phase_that_logs_an_error_fails_the_run(
    tmp_path: Path, command: tuple[str, ...], phase: str
) -> None:
    """A9: the malformed object was skipped, logged at ERROR, and the run exited 0."""
    repo = _tutorial(tmp_path)
    broken = repo / "objects" / "rules" / "broken.yaml"
    broken.write_text("name: Broken\nmetadata: [unclosed\n", encoding="utf-8")
    payload = _failure(_invoke(repo, *command))
    assert payload["phase"] == phase
    message = str(payload["message"])
    # Readable, as a log line reads: never the raw event slug (D14).
    assert message.startswith(f"{phase}: logged an error: Malformed object yaml · path: ")
    assert str(broken) in message


def test_a_raise_after_a_logged_error_reports_both(tmp_path: Path) -> None:
    """The rule's dangling reference is the symptom; the skipped objective is the cause."""
    repo = _tutorial(tmp_path)
    objective = repo / "objects" / "objectives" / "credential-access-objective.yaml"
    text = objective.read_text(encoding="utf-8")
    objective.write_text(f"{text}\nbroken: [unclosed\n", encoding="utf-8")
    payload = _failure(_invoke(repo, "generate", "docs"))
    message = str(payload["message"])
    assert message.startswith(
        "docs: Exception: detection_model 00000000-0000-4000-8002-000000000001 does not exist "
        f"in the catalogue while rendering {_RULE}; "
        "logged an error: Malformed object yaml · path: "
    )
    assert str(objective) in message


def test_a_healthy_tutorial_still_generates(tmp_path: Path) -> None:
    result = _invoke(_tutorial(tmp_path), "generate")
    assert result.exit_code == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["ok"] is True


def test_describe_exception_keeps_the_type() -> None:
    assert describe_exception(KeyError("tlp")) == "KeyError: 'tlp'"
    assert describe_exception(ValueError()) == "ValueError"


def test_rendering_names_the_innermost_object_once() -> None:
    with pytest.raises(ObjectGenerationError) as caught, rendering("outer"), rendering("inner"):
        raise KeyError("tlp")
    assert str(caught.value) == "KeyError: 'tlp' while rendering inner"
    assert isinstance(caught.value.__cause__, KeyError)


def test_failing_phase_names_the_phase_on_a_raise() -> None:
    with pytest.raises(GenerationPhaseError) as caught, failing_phase("exports"), rendering("u-1"):
        raise KeyError("tlp")
    assert caught.value.phase == "exports"
    assert str(caught.value) == "exports: KeyError: 'tlp' while rendering u-1"


def test_failing_phase_fails_on_logged_errors_and_ignores_warnings() -> None:
    logger = logging.getLogger("opentide.tests.generate_errors")
    with failing_phase("vocabs"):
        logger.warning("only a warning")
    with pytest.raises(GenerationPhaseError) as caught, failing_phase("vocabs"):
        logger.error("first  broken\nthing")
        logger.error("second")
    assert str(caught.value) == "vocabs: logged 2 errors, first: first broken thing"
    assert not any(
        type(handler).__name__ == "_ErrorRecords" for handler in logging.getLogger().handlers
    )


def test_failing_phase_counts_a_repeated_error_once() -> None:
    """Only the event and its fields identify an error; not when, nor their order."""
    logger = logging.getLogger("opentide.tests.generate_errors")
    with pytest.raises(GenerationPhaseError) as caught, failing_phase("schemas"):
        logger.error({"event": "malformed_object_yaml", "path": "a.yaml", "timestamp": "09:00:00"})
        logger.error({"timestamp": "09:00:01", "path": "a.yaml", "event": "malformed_object_yaml"})
        logger.error({"event": "malformed_object_yaml", "path": "b.yaml"})
    assert (
        str(caught.value) == "schemas: logged 2 errors, first: Malformed object yaml · path: a.yaml"
    )


def test_a_model_that_does_not_validate_is_one_readable_line() -> None:
    """generate docs printed Pydantic's report: the internal model name, the input dump
    and an errors.pydantic.dev link (post-merge end-to-end run)."""
    from pydantic import BaseModel, ValidationError

    class DetectionRule_v1_1(BaseModel):
        name: str
        description: str
        version: int

    with pytest.raises(ValidationError) as caught:
        DetectionRule_v1_1.model_validate({"name": "LSASS access", "version": "x"})
    text = describe_exception(caught.value)
    assert text == (
        "'LSASS access' does not validate: description: field required (and 1 more); "
        "opentide validate shows each finding"
    )
    assert "pydantic.dev" not in text
    assert "DetectionRule_v1_1" not in text
