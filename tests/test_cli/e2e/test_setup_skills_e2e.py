"""CLI E2E: setup skills discover/show are subcommands, not a PATH."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e


@pytest.fixture(autouse=True)
def _bundled_skills_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.services.setup import skills_registry as registry

    monkeypatch.setattr(registry, "_fetch_remote_manifest", lambda **_: None)
    registry.clear_manifest_cache()
    yield
    registry.clear_manifest_cache()


def test_skills_discover_json(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli("setup", "skills", "discover", "--path", str(tide_corpus_repo))
    payload = assert_json_ok(result)
    assert payload["count"] >= 1
    slugs = {item["slug"] for item in payload["skills"]}
    assert "opentide-detection-rule" in slugs
    assert "detection-engineering" in slugs
    assert payload["manifest_source"] == "bundled"


def test_skills_discover_human_table(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli(
        "setup",
        "skills",
        "discover",
        "--path",
        str(tide_corpus_repo),
        json_output=False,
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "DEPRECATED" not in combined
    assert "opentide-detection-rule" in combined or "OpenTide Skills" in combined


def test_skills_show_json(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli(
        "setup",
        "skills",
        "show",
        "opentide-detection-rule",
        "--path",
        str(tide_corpus_repo),
    )
    payload = assert_json_ok(result)
    assert payload["skill"]["slug"] == "opentide-detection-rule"


def test_skills_show_missing_json(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli(
        "setup",
        "skills",
        "show",
        "no-such-skill-xyz",
        "--path",
        str(tide_corpus_repo),
    )
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload.get("ok") is False
    assert "error" in payload
