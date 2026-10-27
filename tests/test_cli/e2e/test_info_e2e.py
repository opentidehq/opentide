"""CLI E2E: info command snapshots."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def _stable_info_payload(payload: dict[str, object]) -> dict[str, object]:
    """Drop volatile paths and version strings from info JSON snapshots."""
    return {
        "counts": payload["counts"],
        "platforms": payload["platforms"],
    }


def test_info_json_snapshot(invoke_cli, snapshot) -> None:
    result = invoke_cli("info")
    payload = assert_json_ok(result)
    assert _stable_info_payload(payload) == snapshot(name="info_json")


def test_info_no_color_renders_platform_table(cli_runner, tide_corpus_repo, monkeypatch) -> None:
    from opentide.cli import app

    monkeypatch.setenv("TERM", "xterm-256color")
    result = cli_runner.invoke(
        app,
        ["--no-color", "--repo", str(tide_corpus_repo), "info"],
    )
    assert result.exit_code == 0
    plain = result.stdout
    assert "\x1b[" not in plain
    # Label and value columns, not a boxed "opentide Info" table; the counts are
    # the outcome line's, once (post-merge end-to-end run).
    assert "opentide Info" not in plain and "┏" not in plain
    assert "Parse errors" not in plain
    assert "9 rules" in plain
    rows = [" ".join(line.split()) for line in plain.splitlines()]
    assert any(row.startswith("version ") for row in rows)
    assert "Splunk Enterprise Security enabled · deploy, validate" in rows


def test_info_coverage_matches_top_level_techniques(invoke_cli, corpus_rule_uuids) -> None:
    result = invoke_cli("info", "--technique", "T1059", "coverage")
    payload = assert_json_ok(result)
    coverage = payload["coverage"]
    assert coverage["technique"] == "T1059"
    assert coverage["count"] >= 1
    assert corpus_rule_uuids["sentinel"] in coverage["rules"]
