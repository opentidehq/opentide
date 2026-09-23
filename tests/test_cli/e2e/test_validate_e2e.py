"""CLI E2E: validate command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import hidden_modules, uncomment_tenants

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
    platform: str,
    expects_supported: bool,
) -> None:
    """No validator mock: the default path must pass on a stock install (#239, #261)."""
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
        assert payload.get("mode") == "offline-syntax"
        assert payload.get("status") == "passed"
        assert payload.get("checked", 0) >= 1
    else:
        assert result.exit_code != 0
        if "{" in result.stdout:
            body = parse_cli_json(result)
            assert body.get("supported") is False


def test_validate_query_without_plan_or_wide(invoke_cli) -> None:
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


def _break_sentinel_query(repo: Path) -> None:
    path = repo / "Objects" / "Detection Rules" / "rule-0001-sentinel-kql.yaml"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("| where EventID == 4688", '| where Account == "unterminated'),
        encoding="utf-8",
    )


def test_validate_query_fails_on_broken_syntax(invoke_cli, tide_corpus_repo: Path) -> None:
    """A malformed query must fail the command, not be waved through (#245, #261)."""
    _break_sentinel_query(tide_corpus_repo)
    result = invoke_cli("validate", "query", "--platform", "sentinel")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert payload["mode"] == "offline-syntax"
    (finding,) = payload["findings"]
    assert finding["code"] == "unterminated_string"
    assert finding["field"] == "configurations.sentinel.query"
    assert finding["uuid"] == "00000000-0000-4000-8003-000000000001"


_VALID_BUT_UNUSUAL = {
    "sentinel_one": (
        "rule-0004-sentinel-one-s1ql.yaml",
        '- query: EventType = "Process Create"',
        "- query: "
        + json.dumps('EventType = "Process Creation" || EventType = "Process Termination"'),
    ),
    "carbon_black_cloud": (
        "rule-0005-carbon-black-lucene.yaml",
        "query: process_name:cmd.exe",
        "query: " + json.dumps(r"process_cmdline:*iex\(* AND process_pid:[1000 TO 2000}"),
    ),
    "sentinel": (
        "rule-0001-sentinel-kql.yaml",
        "query: |\n      SecurityEvent\n",
        'query: |\n      let marker = ```\n      it\'s "quoted" (and open\n      ```;\n'
        "      SecurityEvent\n",
    ),
}


@pytest.mark.parametrize("platform", sorted(_VALID_BUT_UNUSUAL))
def test_validate_query_accepts_valid_but_unusual_syntax(
    invoke_cli, tide_corpus_repo: Path, platform: str
) -> None:
    """S1QL ``||``, Lucene escapes and mixed ranges, KQL ``` strings are all valid.

    The offline check is the default CI path, so rejecting them failed every
    pipeline that deployed such a rule.
    """
    name, old, new = _VALID_BUT_UNUSUAL[platform]
    path = tide_corpus_repo / "Objects" / "Detection Rules" / name
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")

    result = invoke_cli("validate", "query", "--platform", platform)
    payload = assert_json_ok(result)
    assert (payload["mode"], payload["status"], payload["findings"]) == (
        "offline-syntax",
        "passed",
        [],
    )


def test_validate_query_offline_needs_no_vendor_sdk(invoke_cli) -> None:
    """Issue #239: the stock install has no azure package and must still work."""
    with hidden_modules("azure"):
        payload = assert_json_ok(invoke_cli("validate", "query", "--platform", "sentinel"))
    assert payload["mode"] == "offline-syntax"
    assert payload["language"] == "kql"


@pytest.fixture
def sentinel_tenant(tide_corpus_repo: Path) -> None:
    """``--live`` stops before the engine when no tenant is configured (#314)."""
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")


@pytest.mark.usefixtures("sentinel_tenant")
def test_validate_query_live_without_sdk_reports_the_extra(invoke_cli) -> None:
    """--live is allowed to fail, but with advice instead of a traceback (#239)."""
    with hidden_modules("azure", purge=("opentide.platforms.sentinel",)):
        result = invoke_cli("validate", "query", "--platform", "sentinel", "--live", "--wide")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["mode"] == "live"
    assert payload["status"] == "failed"
    assert "opentide[sentinel]" in payload["advice"]


@pytest.mark.usefixtures("sentinel_tenant")
def test_validate_query_live_uses_the_platform_engine(invoke_cli, mock_query_validators) -> None:
    result = invoke_cli("validate", "query", "--platform", "sentinel", "--live", "--wide")
    payload = assert_json_ok(result)
    assert payload["mode"] == "live"
    assert payload["status"] == "passed"


@pytest.mark.usefixtures("sentinel_tenant")
def test_validate_query_loads_only_the_requested_engine(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #246: a sentinel-only run must not import every vendor engine."""
    from opentide.platforms import plugins

    imported: list[str] = []
    original = plugins.PlatformLoader.import_engine

    def _record(module_path: str):
        imported.append(module_path)
        return original(module_path)

    monkeypatch.setattr(plugins.PlatformLoader, "import_engine", staticmethod(_record))
    invoke_cli("validate", "query", "--platform", "sentinel", "--live", "--wide")
    assert imported
    assert not [path for path in imported if "crowdstrike" in path or "harfanglab" in path]


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
