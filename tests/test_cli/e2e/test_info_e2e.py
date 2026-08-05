"""CLI E2E: info command snapshots."""

from __future__ import annotations

import re

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def _stable_info_payload(payload: dict[str, object]) -> dict[str, object]:
    """Drop volatile paths and version strings from info JSON snapshots."""
    return {
        "counts": payload["counts"],
        "platforms": payload["platforms"],
    }


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_info_json_snapshot(invoke_cli, snapshot) -> None:
    result = invoke_cli("info")
    payload = assert_json_ok(result)
    assert _stable_info_payload(payload) == snapshot(name="info_json")


def test_info_no_color_renders_platform_table(cli_runner, tide_corpus_repo) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(
        app,
        ["--no-color", "--repo", str(tide_corpus_repo), "info"],
    )
    assert result.exit_code == 0
    plain = _strip_ansi(result.stdout)
    assert "OpenTide Info" in plain
    assert "Rules" in plain and "8" in plain
    assert "Splunk Enterprise Security" in plain
    assert "enabled=True" in plain
