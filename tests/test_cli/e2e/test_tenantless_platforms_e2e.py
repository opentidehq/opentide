"""CLI E2E: an enabled platform whose ``[[tenants]]`` block is still commented out (#314).

``setup repo --platform <p>`` writes ``enabled = true`` and leaves the tenant
example commented out. A real deploy and a live query check must stop with a
structured failure before any platform engine loads; a dry run still previews
the payloads but must not report the platform as deployed.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable, Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from tests.corpus_support import TIDE_CORPUS_ROOT
from tests.test_cli.conftest import parse_cli_json
from tests.test_cli.e2e.helpers import uncomment_tenants
from typer.testing import Result

from opentide.cli.enums import QUERY_VALIDATION_PLATFORMS, DetectionPlatform

pytestmark = pytest.mark.cli_e2e

CORPUS_RULES = TIDE_CORPUS_ROOT / "Objects" / "Detection Rules"
PLATFORMS = [pytest.param(platform, id=platform.value) for platform in DetectionPlatform]
LIVE_PLATFORMS = [p for p in PLATFORMS if p.values[0].value in QUERY_VALIDATION_PLATFORMS]
NO_QUERY_PLATFORMS = [p for p in PLATFORMS if p.values[0].value not in QUERY_VALIDATION_PLATFORMS]
OUTPUT_MODES = [pytest.param(True, id="json"), pytest.param(False, id="human")]


def _config_path(platform: str) -> str:
    return f".opentide/configurations/platforms/{platform}.toml"


def _corpus_rule(platform: str) -> Path:
    for path in sorted(CORPUS_RULES.glob("rule-*.yaml")):
        configurations = yaml.safe_load(path.read_text(encoding="utf-8"))["configurations"]
        if list(configurations) == [platform]:
            return path
    raise AssertionError(f"tide_corpus has no single-platform rule for {platform}")


@pytest.fixture
def tenantless_repo(invoke_cli, tmp_path: Path) -> Callable[[list[str]], Path]:
    """Scaffold with ``setup repo`` exactly as a first user would, then add rules."""

    def _scaffold(platforms: list[str]) -> Path:
        repo = tmp_path / "detections"
        flags = [arg for platform in platforms for arg in ("--platform", platform)]
        setup = invoke_cli(
            "setup",
            "repo",
            "--yes",
            "--name",
            "Tenantless Detections",
            "--org",
            "Example Corp",
            *flags,
            "--path",
            str(repo),
            repo=tmp_path,
        )
        assert setup.exit_code == 0, setup.stdout + setup.stderr
        rules = repo / "objects" / "rules"
        rules.mkdir(parents=True, exist_ok=True)
        for platform in platforms:
            config = (repo / _config_path(platform)).read_text(encoding="utf-8")
            assert re.search(r"^enabled = true$", config, re.MULTILINE)
            assert not re.search(r"^\[\[tenants\]\]", config, re.MULTILINE)
            shutil.copy(_corpus_rule(platform), rules / f"{platform}-rule.yaml")
        return repo

    return _scaffold


@pytest.fixture
def engine_imports(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record platform engine imports without stubbing them."""
    from opentide.platforms import plugins

    imported: list[str] = []
    original = plugins.PlatformLoader.import_engine

    def _record(module_path: str):
        imported.append(module_path)
        return original(module_path)

    monkeypatch.setattr(plugins.PlatformLoader, "import_engine", staticmethod(_record))
    return imported


@pytest.fixture
def mock_deployers(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Stand in for every deployer at the network boundary (dry-run only)."""
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return dict.fromkeys(platforms, deployer)

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    return deployer


def _run(invoke_cli, repo: Path, json_output: bool, *args: str) -> tuple[Result, str]:
    flags = () if json_output else ("--no-color",)
    result = invoke_cli(
        *flags, *args, repo=repo, json_output=json_output, extra_env={"COLUMNS": "200"}
    )
    output = result.stdout + result.stderr
    # CliRunner turns an uncaught exception into ``result.exception`` instead of
    # printing the traceback, so checking the text alone would pass vacuously.
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert "Traceback" not in output, output
    assert "Missing tenant configuration" not in output, output
    return result, " ".join(output.split())


@pytest.mark.parametrize("json_output", OUTPUT_MODES)
@pytest.mark.parametrize("platform", PLATFORMS)
def test_deploy_without_tenants_fails_before_loading_an_engine(
    invoke_cli,
    tenantless_repo,
    engine_imports: list[str],
    platform: DetectionPlatform,
    json_output: bool,
) -> None:
    repo = tenantless_repo([platform.value])
    config = _config_path(platform.value)
    message = f"Cannot deploy: {platform.value} has no tenants configured in {config}"

    result, output = _run(invoke_cli, repo, json_output, "deploy", "--platform", platform.value)

    assert result.exit_code == 1, output
    if json_output:
        payload = parse_cli_json(result)
        assert payload["ok"] is False
        assert payload["status"] == "failed"
        assert payload["message"] == message
        assert payload["advice"] == f"add (or uncomment) a [[tenants]] entry in {config}"
        assert payload["missing_tenants"] == {platform.value: config}
        assert payload["deployed"] == []
        assert payload["dry_run"] is False
    else:
        assert f"FATAL: {message}" in output
    assert engine_imports == []


@pytest.mark.parametrize("json_output", OUTPUT_MODES)
@pytest.mark.parametrize("platform", PLATFORMS)
def test_deploy_dry_run_without_tenants_previews_but_does_not_claim_the_platform(
    invoke_cli,
    tenantless_repo,
    mock_deployers: MagicMock,
    platform: DetectionPlatform,
    json_output: bool,
) -> None:
    repo = tenantless_repo([platform.value])
    config = _config_path(platform.value)
    warning = f"{platform.value} has no tenants configured in {config}, so a real deploy would stop"

    result, output = _run(
        invoke_cli, repo, json_output, "deploy", "--platform", platform.value, "--dry-run"
    )

    assert result.exit_code == 0, output
    if json_output:
        payload = parse_cli_json(result)
        assert payload["ok"] is True
        assert payload["status"] == "completed"
        assert payload["dry_run"] is True
        assert payload["deployed"] == []
        assert payload["missing_tenants"] == {platform.value: config}
        assert payload["advice"] == f"add (or uncomment) a [[tenants]] entry in {config}"
        assert payload["warnings"] == [warning]
        (uuid,) = payload["plan"][platform.value]
        assert [item["uuid"] for item in payload["payloads"][platform.value]] == [uuid]
    else:
        assert "OK Deployment completed" in output
        assert f"WARNING {warning}" in output
    mock_deployers.deploy.assert_not_called()


def test_deploy_dry_run_only_flags_the_platform_without_tenants(
    invoke_cli, tenantless_repo, mock_deployers: MagicMock
) -> None:
    repo = tenantless_repo(["sentinel", "splunk"])
    uncomment_tenants(repo / _config_path("sentinel"))

    result, output = _run(invoke_cli, repo, True, "deploy", "--dry-run")

    assert result.exit_code == 0, output
    payload = parse_cli_json(result)
    assert set(payload["plan"]) == {"sentinel", "splunk"}
    assert payload["deployed"] == ["sentinel"]
    assert payload["missing_tenants"] == {"splunk": _config_path("splunk")}
    mock_deployers.deploy.assert_not_called()


@pytest.mark.parametrize("json_output", OUTPUT_MODES)
@pytest.mark.parametrize("platform", LIVE_PLATFORMS)
def test_live_query_validation_without_tenants_fails_before_loading_a_validator(
    invoke_cli,
    tenantless_repo,
    engine_imports: list[str],
    platform: DetectionPlatform,
    json_output: bool,
) -> None:
    repo = tenantless_repo([platform.value])
    config = _config_path(platform.value)
    message = (
        f"Cannot run live query validation: {platform.value} has no tenants configured in {config}"
    )

    result, output = _run(
        invoke_cli, repo, json_output, "validate", "query", "--platform", platform.value, "--live"
    )

    assert result.exit_code == 1, output
    if json_output:
        payload = parse_cli_json(result)
        assert payload["ok"] is False
        assert payload["status"] == "failed"
        assert payload["mode"] == "live"
        assert payload["supported"] is True
        assert payload["message"] == message
        assert payload["advice"] == f"add (or uncomment) a [[tenants]] entry in {config}"
        assert payload["missing_tenants"] == {platform.value: config}
    else:
        assert f"FATAL: {message}" in output
    assert engine_imports == []


@pytest.mark.parametrize("json_output", OUTPUT_MODES)
@pytest.mark.parametrize("platform", NO_QUERY_PLATFORMS)
def test_live_query_validation_stays_unsupported_without_tenants(
    invoke_cli,
    tenantless_repo,
    engine_imports: list[str],
    platform: DetectionPlatform,
    json_output: bool,
) -> None:
    repo = tenantless_repo([platform.value])

    result, output = _run(
        invoke_cli, repo, json_output, "validate", "query", "--platform", platform.value, "--live"
    )

    assert result.exit_code == 1, output
    if json_output:
        payload = parse_cli_json(result)
        assert payload["supported"] is False
        assert payload["status"] == "failed"
        assert "missing_tenants" not in payload
    assert f"query validation not supported for {platform.value}" in output
    assert engine_imports == []


@pytest.mark.parametrize("platform", LIVE_PLATFORMS)
def test_offline_query_validation_does_not_need_tenants(
    invoke_cli, tenantless_repo, platform: DetectionPlatform
) -> None:
    repo = tenantless_repo([platform.value])

    result, output = _run(invoke_cli, repo, True, "validate", "query", "--platform", platform.value)

    assert result.exit_code == 0, output
    payload = parse_cli_json(result)
    assert payload["ok"] is True
    assert payload["status"] == "passed"
    assert payload["mode"] == "offline-syntax"
    assert payload["checked"] == 1
