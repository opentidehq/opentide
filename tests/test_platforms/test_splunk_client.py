"""Splunk client setup resolution."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest
from structlog.testing import CapturingLogger
from tests.corpus_support import clear_runtime_caches

from opentide.core.registry import OpenTide
from opentide.platforms.registry import PlatformsRegistry
from opentide.platforms.splunk import client as splunk_client
from opentide.platforms.splunk.client import correct_timerange_mode

_TENANT_TOML = """\
[platform]
enabled = true
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
proxy = false
ssl = false
url = "https://splunk.example"
port = "8089"
token = "token"
app = "search"
"""


@pytest.fixture
def splunk_log(monkeypatch: pytest.MonkeyPatch) -> CapturingLogger:
    captured = CapturingLogger()
    monkeypatch.setattr(splunk_client, "logger", captured)
    return captured


def _warnings(log: CapturingLogger) -> list[object]:
    return [call.args[0] for call in log.calls if call.method_name == "warning"]


@pytest.mark.parametrize("unset", [None, ""])
def test_unset_frequency_scheduling_uses_random_without_warning(
    splunk_log: CapturingLogger, unset: str | None
) -> None:
    assert correct_timerange_mode(unset) == "random"
    assert _warnings(splunk_log) == []


@pytest.mark.parametrize("mode", ["random", "current", "custom"])
def test_documented_frequency_scheduling_modes_pass_through(
    splunk_log: CapturingLogger, mode: str
) -> None:
    assert correct_timerange_mode(mode) == mode
    assert _warnings(splunk_log) == []


def test_invalid_frequency_scheduling_warns_once_and_uses_current(
    splunk_log: CapturingLogger,
) -> None:
    assert correct_timerange_mode("bogus") == "current"
    assert _warnings(splunk_log) == ["frequency_scheduling_is_not_valid"]
    (call,) = (c for c in splunk_log.calls if c.method_name == "warning")
    assert "'bogus'" in str(call.kwargs["detail"])


def _legacy_setup(repo: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str | None], None]:
    """The corpus enables Splunk with a ``[setup]`` table and ``$SPLUNK_*`` secrets."""
    for name, value in {
        "SPLUNK_URL": "https://splunk.example",
        "SPLUNK_PORT": "8089",
        "SPLUNK_APP": "search",
        "SPLUNK_TOKEN": "token",
    }.items():
        monkeypatch.setenv(name, value)
    config = repo / ".opentide" / "configurations" / "systems" / "splunk.toml"
    original = config.read_text(encoding="utf-8")

    def _write(value: str | None) -> None:
        line = "" if value is None else f'frequency_scheduling = "{value}"'
        text = re.sub(r"^frequency_scheduling = .*$", line, original, flags=re.MULTILINE)
        config.write_text(text, encoding="utf-8")

    return _write


def _tenant_setup(repo: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str | None], None]:
    """A ``[[tenants]]`` platform file, as ``opentide setup`` writes it."""
    platforms = repo / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True, exist_ok=True)

    def _write(value: str | None) -> None:
        line = "" if value is None else f'frequency_scheduling = "{value}"\n'
        (platforms / "splunk.toml").write_text(_TENANT_TOML + line, encoding="utf-8")

    return _write


@pytest.fixture(params=["legacy-setup", "tenant"])
def splunk_frequency(
    request: pytest.FixtureRequest,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[str | None], None]:
    """Write an enabled Splunk config whose ``frequency_scheduling`` is *value* (None: absent)."""
    if request.param == "tenant":
        (tide_corpus_repo / ".opentide" / "configurations" / "systems" / "splunk.toml").unlink()
        writer = _tenant_setup(tide_corpus_repo, monkeypatch)
    else:
        writer = _legacy_setup(tide_corpus_repo, monkeypatch)
    monkeypatch.setattr(OpenTide, "Platforms", PlatformsRegistry())

    def _apply(value: str | None) -> None:
        writer(value)
        clear_runtime_caches()

    return _apply


def test_enabled_tenant_with_invalid_frequency_warns_once(
    splunk_frequency, splunk_log: CapturingLogger
) -> None:
    splunk_frequency("bogus")
    platform = OpenTide.Platforms["splunk"]
    assert platform.enabled is True
    assert splunk_log.calls == []
    deployer = platform.deployer
    assert platform.deployer is deployer
    assert getattr(deployer, "TIMERANGE_MODE", None) == "current"
    assert _warnings(splunk_log) == ["frequency_scheduling_is_not_valid"]


def test_enabled_tenant_without_frequency_uses_random_silently(
    splunk_frequency, splunk_log: CapturingLogger
) -> None:
    splunk_frequency(None)
    deployer = OpenTide.Platforms["splunk"].deployer
    assert getattr(deployer, "TIMERANGE_MODE", None) == "random"
    assert _warnings(splunk_log) == []
