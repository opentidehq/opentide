"""CLI E2E: exit code behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli.conftest import LOCAL_SHELL_UNSET
from tests.test_cli.e2e.helpers import EVERY_RULE

pytestmark = pytest.mark.cli_e2e

DEPLOY_PLATFORMS = (
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "carbon_black_cloud",
    "crowdstrike",
    "harfanglab",
)

# Every command that reads the object catalogue, with the exit code it documents
# for a workspace that has no objects yet. `deploy metadata` is the reserved stub.
EMPTY_CATALOGUE_COMMANDS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("validate",), 0),
    (("validate", "--strict"), 0),
    (("lint",), 0),
    (("lint", "--strict"), 0),
    (("info",), 0),
    (("generate",), 0),
    (("generate", "docs"), 0),
    (("generate", "exports"), 0),
    # Without --live: the offline check, which finds no query (skipped, exit 0).
    (("validate", "query"), 0),
    (("validate", "query", "--platform", "sentinel"), 0),
    (("validate", "--queries", "warn"), 0),
    (("validate", "--queries", "off"), 0),
    (("validate", "query", "--platform", "sentinel", "--live"), 0),
    *(
        (("deploy", "--dry-run", *EVERY_RULE, "--platform", platform), 0)
        for platform in DEPLOY_PLATFORMS
    ),
    (("deploy", "--dry-run", *EVERY_RULE), 0),
    (("deploy", "--dry-run", "--strategy", "PREVIEW", "--all"), 0),
    (("deploy", "--dry-run", "--strategy", "RELEASE", "--all"), 0),
    (("deploy", *EVERY_RULE, "--platform", "sentinel"), 0),
    (("deploy", *EVERY_RULE), 0),
    (("deploy", "--strategy", "RELEASE", "--all"), 0),
    (("deploy", "metadata", "--platform", "sentinel"), 2),
    # 0.17.0: a deploy names its strategy, and outside CI without --all it reads
    # the last commit, which an empty folder that is no git checkout lacks.
    (("deploy", "--dry-run"), 2),
    (("deploy", "--dry-run", "--plan", "STAGING"), 2),
    (("deploy", "--dry-run", "--strategy", "PREVIEW"), 1),
)


def _empty_workspace(root: Path, shape: str) -> Path:
    """A workspace with no objects, in the shapes a first user actually has."""
    workspace = root / shape
    workspace.mkdir()
    if shape == "opentide-without-objects":
        (workspace / ".opentide").mkdir()
    elif shape == "rules-folder-with-gitkeep":
        rules = workspace / "objects" / "rules"
        rules.mkdir(parents=True)
        (rules / ".gitkeep").touch()
    return workspace


def test_validation_warning_exits_zero_without_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.exit_codes import validation_exit_code

    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    assert validation_exit_code(strict=False) == 0
    assert validation_exit_code(strict=True) == 1


def test_cli_exit_policy_never_returns_19(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.exit_codes import deployment_exit_code, validation_exit_code
    from opentide.deployment.ci import CIEnvironment

    monkeypatch.setenv("VALIDATION_WARNING_RAISED", "1")
    monkeypatch.setenv("DEPLOYMENT_WARNING_RAISED", "1")
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    monkeypatch.setattr(
        CIEnvironment,
        "_check_ci_environment",
        lambda self: CIEnvironment.CIPlatforms.GitlabCI,
    )
    assert validation_exit_code() != 19
    assert deployment_exit_code() != 19


@pytest.mark.parametrize("json_output", [True, False], ids=["json", "human"])
@pytest.mark.parametrize(
    "shape", ["empty-directory", "opentide-without-objects", "rules-folder-with-gitkeep"]
)
@pytest.mark.parametrize(
    ("argv", "expected_exit"),
    EMPTY_CATALOGUE_COMMANDS,
    ids=[" ".join(argv) for argv, _ in EMPTY_CATALOGUE_COMMANDS],
)
def test_catalogue_commands_in_an_empty_workspace(
    invoke_cli,
    refuse_deployment_engines: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: tuple[str, ...],
    expected_exit: int,
    shape: str,
    json_output: bool,
) -> None:
    """A workspace without objects is an empty catalogue, never an ``OSError``.

    ``deploy`` alone listed ``objects/rules`` directly and exited 1 with
    ``[Errno 2] No such file or directory`` (#300) while every sibling reported
    zero objects.
    """
    for name in LOCAL_SHELL_UNSET:
        monkeypatch.delenv(name, raising=False)
    workspace = _empty_workspace(tmp_path, shape)

    result = invoke_cli(*argv, repo=workspace, json_output=json_output)

    output = result.stdout + result.stderr
    assert result.exception is None or isinstance(result.exception, SystemExit), output
    assert result.exit_code == expected_exit, output
    for marker in ("Traceback", "Errno", "No such file or directory"):
        assert marker not in output, output
    assert refuse_deployment_engines == []
    if argv[:2] == ("validate", "query") and "--live" not in argv:
        assert "query the engine checks" in output, output
    if not json_output:
        if expected_exit == 0:
            assert "FATAL" not in output, output
        return
    payload = json.loads(result.stdout)
    assert {"ok", "status", "message"} <= payload.keys()
    assert payload["ok"] is (expected_exit == 0)
    if argv[0] == "deploy" and "metadata" not in argv and expected_exit != 0:
        assert payload["status"] == "failed"
        assert ("--strategy" if "--strategy" not in argv else "--all") in payload["message"]
    elif argv[0] == "deploy" and "metadata" not in argv:
        assert payload["status"] == "skipped"
        assert payload["dry_run"] is ("--dry-run" in argv)
        assert payload["plan"] == {}
        assert payload["deployed"] == []
