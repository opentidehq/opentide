"""CLI E2E: validate command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e


def test_validate_full_passes(invoke_cli) -> None:
    result = invoke_cli("validate")
    payload = assert_json_ok(result)
    assert payload["checks"]["schema"]["status"] == "passed"
    assert payload["report"]["ok"] is True


def test_validate_scoped_by_uuid(invoke_cli, corpus_rule_uuids) -> None:
    sentinel_uuid = corpus_rule_uuids["sentinel"]
    result = invoke_cli("validate", "--uuid", sentinel_uuid)
    payload = assert_json_ok(result)
    assert payload["report"]["ok"] is True


@pytest.mark.parametrize(
    ("platform", "expects_supported"),
    [
        ("sentinel", True),
        ("defender_for_endpoint", True),
        ("splunk", True),
        ("sentinel_one", True),
        ("carbon_black_cloud", True),
        ("crowdstrike", False),
        ("harfanglab", False),
    ],
)
def test_validate_query_platform_matrix(
    invoke_cli,
    mock_query_validators,
    platform: str,
    expects_supported: bool,
) -> None:
    result = invoke_cli(
        "validate",
        "query",
        "--platform",
        platform,
        "--plan",
        "FULL",
        "--wide",
    )
    if expects_supported:
        payload = assert_json_ok(result)
        assert payload.get("supported") is True
        assert payload.get("status") == "passed"
    else:
        assert result.exit_code != 0
        if "{" in result.stdout:
            body = parse_cli_json(result)
            assert body.get("supported") is False


def test_validate_query_without_plan_or_wide(invoke_cli, mock_query_validators) -> None:
    """Unset DEPLOYMENT_PLAN must not traceback on validate query (issue #164)."""
    result = invoke_cli(
        "validate",
        "query",
        "--platform",
        "sentinel",
        extra_env={"DEPLOYMENT_PLAN": ""},
    )
    payload = assert_json_ok(result)
    assert payload.get("supported") is True
    assert payload.get("status") == "passed"


def _write_threat_cves(repo: Path, identifiers: list[str]) -> None:
    path = repo / "Objects" / "Threat Vectors" / "threat-0001-simulated-actor.yaml"
    text = path.read_text(encoding="utf-8")
    if "\n  cve:" in text:
        return
    block = "  cve:\n" + "".join(f"    - {item}\n" for item in identifiers)
    path.write_text(text.rstrip() + "\n" + block, encoding="utf-8")


def _install_lookup_mock(monkeypatch: pytest.MonkeyPatch, payloads: dict[str, dict]) -> None:
    def _fake_get(self, url, params=None, timeout=None, **kwargs):
        _ = self, params, timeout, kwargs
        response = MagicMock()
        response.status_code = 200
        ident = str(url).rsplit("/", 1)[-1]
        response.json.return_value = payloads.get(ident, {})
        return response

    monkeypatch.setattr("requests.Session.get", _fake_get)


def test_validate_cve_check_fails_unknown_identifier(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_threat_cves(tide_corpus_repo, ["CVE-2024-BAD"])
    _install_lookup_mock(monkeypatch, {})
    result = invoke_cli("validate", "--check", "cve")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["ok"] is False
    assert payload["check"] == "cve"
    assert payload["status"] == "failed"
    dumped = result.stdout
    assert "invalid_cve" in dumped
    assert "CVE-2024-BAD" in dumped


def test_validate_cve_check_passes_known_and_gcve0(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_vulnerability_lookup.test_client import CVE5_PAYLOAD

    _write_threat_cves(tide_corpus_repo, ["cve-2024-3094", "GCVE-0-2024-3094"])
    _install_lookup_mock(monkeypatch, {"CVE-2024-3094": CVE5_PAYLOAD})
    result = invoke_cli("validate", "--check", "cve")
    payload = assert_json_ok(result)
    assert payload["check"] == "cve"
    assert payload["status"] == "passed"


def test_validate_default_checks_do_not_include_cve(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_threat_cves(tide_corpus_repo, ["CVE-2024-BAD"])
    called = {"http": False}

    def _fake_get(self, url, params=None, timeout=None, **kwargs):
        called["http"] = True
        raise AssertionError(f"default validate must not call Vulnerability-Lookup: {url}")

    monkeypatch.setattr("requests.Session.get", _fake_get)
    result = invoke_cli("validate")
    payload = assert_json_ok(result)
    assert "cve" not in payload["checks"]
    assert called["http"] is False
