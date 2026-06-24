"""CLI E2E: info command snapshots."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def test_info_json_snapshot(invoke_cli, snapshot) -> None:
    result = invoke_cli("info")
    payload = assert_json_ok(result)
    assert payload == snapshot(name="info_json")


def test_info_no_color_text_snapshot(cli_runner, tide_corpus_repo, snapshot) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(
        app,
        ["--no-color", "--repo", str(tide_corpus_repo), "info"],
    )
    assert result.exit_code == 0
    assert snapshot(name="info_no_color") == result.stdout
