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


def _stable_info_text(stdout: str) -> str:
    """Normalize version and temp corpus paths in human-readable info output."""
    text = re.sub(r"0\.\d+\.dev\S+", "<version>", stdout)
    return re.sub(r"/tmp/pytest-of-\S+/corpus", "<corpus>", text)


def test_info_json_snapshot(invoke_cli, snapshot) -> None:
    result = invoke_cli("info")
    payload = assert_json_ok(result)
    assert _stable_info_payload(payload) == snapshot(name="info_json")


def test_info_no_color_text_snapshot(cli_runner, tide_corpus_repo, snapshot) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(
        app,
        ["--no-color", "--repo", str(tide_corpus_repo), "info"],
    )
    assert result.exit_code == 0
    assert snapshot(name="info_no_color") == _stable_info_text(result.stdout)
