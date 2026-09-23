"""CLI E2E: a platform nobody enabled or configured does not log (#295).

Listing platforms used to build every deployer and validator, so each client
checked a tenant setup that was never written: the quickstart ``info`` printed
the Splunk ``frequency_scheduling`` warning twice in a Sentinel-only repo and
in an empty directory. The subprocess guard for the whole quickstart path is
``test_quickstart_warnings_subprocess_e2e.py``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.conftest import assert_json_ok
from tests.test_cli.e2e.helpers import write_tutorial_objects
from typer.testing import Result

from opentide.core.logging import LoggingConfig, init_logging
from opentide.core.registry import OpenTide
from opentide.mcp_server.resources import resource_platforms
from opentide.platforms.registry import PlatformsRegistry

pytestmark = pytest.mark.cli_e2e

_NOISY = frozenset({"warning", "error", "critical"})
_FREQUENCY_EVENTS = frozenset(
    {"frequency_scheduling_is_not_valid", "the_frequency_scheduling_setting_was_not_correct_set"}
)

_DISABLED_SPLUNK = """\
[platform]
enabled = false
identifier = "splunk"
name = "Splunk Enterprise"
subschema = "Splunk Sub Schema"
description = "Splunk"
flags = []

[[tenants]]
name = "Default"
description = "Default Splunk deployment target"
deployment = "ALWAYS"
[tenants.setup]
url = "$SPLUNK_URL"
port = "$SPLUNK_PORT"
token = "$SPLUNK_TOKEN"
app = "search"
frequency_scheduling = "bogus"
"""


@pytest.fixture(autouse=True)
def _fresh_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    """A registry an earlier test already loaded builds nothing and would hide a regression."""
    monkeypatch.setattr(OpenTide, "Platforms", PlatformsRegistry())


@pytest.fixture
def tutorial_repo(invoke_cli, tmp_path: Path) -> Path:
    """The Sentinel-only repository the quickstart builds."""
    fresh = tmp_path / "tutorial-detections"
    setup = invoke_cli(
        "setup",
        "--yes",
        "--name",
        "Tutorial Detections",
        "--org",
        "Example Corp",
        "--platform",
        "sentinel",
        "--path",
        str(fresh),
        repo=tmp_path,
    )
    assert_json_ok(setup)
    write_tutorial_objects(fresh)
    return fresh


@pytest.fixture
def empty_dir(tmp_path: Path) -> Path:
    empty = tmp_path / "empty"
    empty.mkdir()
    return empty


def _records(result: Result) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in result.stderr.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "logger" in record:
            records.append(record)
    return records


def _noisy(result: Result) -> list[tuple[object, object]]:
    return [(r["logger"], r["event"]) for r in _records(result) if r.get("level") in _NOISY]


def _frequency_warnings(result: Result) -> list[dict[str, object]]:
    return [r for r in _records(result) if r.get("event") in _FREQUENCY_EVENTS]


def _platform_rows(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    rows = payload["platforms"]
    assert isinstance(rows, list)
    return {row["name"]: row for row in rows}


def test_info_in_a_sentinel_only_repo_does_not_warn(invoke_cli, tutorial_repo: Path) -> None:
    result = invoke_cli("info", repo=tutorial_repo)
    rows = _platform_rows(assert_json_ok(result))
    assert rows["sentinel"]["enabled"] is True
    assert rows["splunk"] == {
        "name": "splunk",
        "enabled": False,
        "can_deploy": True,
        "can_validate": True,
    }
    assert _noisy(result) == []


def test_info_in_an_empty_directory_does_not_warn(invoke_cli, empty_dir: Path) -> None:
    result = invoke_cli("info", repo=empty_dir)
    rows = _platform_rows(assert_json_ok(result))
    assert not any(row["enabled"] for row in rows.values())
    assert _noisy(result) == []


def test_info_leaves_a_disabled_splunk_tenant_unread(
    invoke_cli, tutorial_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its ``$SPLUNK_*`` secrets are unset and its ``frequency_scheduling`` is invalid."""
    for name in ("SPLUNK_URL", "SPLUNK_PORT", "SPLUNK_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    platforms = tutorial_repo / ".opentide" / "configurations" / "platforms"
    (platforms / "splunk.toml").write_text(_DISABLED_SPLUNK, encoding="utf-8")

    result = invoke_cli("info", repo=tutorial_repo)
    assert _platform_rows(assert_json_ok(result))["splunk"]["enabled"] is False
    assert _noisy(result) == []


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_initialise_and_platforms_resource_build_no_client(
    tutorial_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SDK and MCP path: ``OpenTide.initialise()`` then ``opentide://platforms``.

    Records are read from the stdlib root logger: ``capture_logs`` misses a
    logger that was cached before an earlier CLI call reconfigured structlog.
    """
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tutorial_repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tutorial_repo))
    clear_runtime_caches()
    init_logging(LoggingConfig(json_output=True), force=True)
    captured = _Records()
    logging.getLogger().addHandler(captured)

    OpenTide.initialise()
    platforms = {row["name"]: row for row in json.loads(resource_platforms())}

    assert platforms["splunk"]["enabled"] is False
    assert platforms["splunk"]["can_deploy"] is True
    assert [(r.name, r.levelname) for r in captured.records if r.levelno >= logging.WARNING] == []
    assert [r.name for r in captured.records if r.name.startswith("opentide.platforms.")] == []


def test_an_enabled_splunk_tenant_with_an_invalid_frequency_warns_once_on_deploy(
    invoke_cli,
    tide_corpus_repo: Path,
    corpus_rule_uuids: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "SPLUNK_URL": "https://splunk.example",
        "SPLUNK_PORT": "8089",
        "SPLUNK_APP": "search",
        "SPLUNK_TOKEN": "token",
    }.items():
        monkeypatch.setenv(name, value)
    config = tide_corpus_repo / ".opentide" / "configurations" / "systems" / "splunk.toml"
    config.write_text(
        re.sub(
            r"^frequency_scheduling = .*$",
            'frequency_scheduling = "bogus"',
            config.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        ),
        encoding="utf-8",
    )

    info = invoke_cli("info")
    assert _platform_rows(assert_json_ok(info))["splunk"]["enabled"] is True
    assert _frequency_warnings(info) == []

    deploy = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "splunk",
        "--plan",
        "FULL",
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(deploy)
    assert corpus_rule_uuids["splunk"] in payload["plan"]["splunk"]
    (warning,) = _frequency_warnings(deploy)
    assert warning["event"] == "frequency_scheduling_is_not_valid"
    assert warning["logger"] == "opentide.platforms.splunk.client"
    assert warning["level"] == "warning"
