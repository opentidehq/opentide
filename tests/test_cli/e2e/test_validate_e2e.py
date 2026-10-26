"""CLI E2E: validate command."""

from __future__ import annotations

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


@pytest.mark.parametrize("check", [(), ("--check", "schema")])
def test_validate_without_metadata_schema_fails_the_schema_check(
    invoke_cli, tide_corpus_repo: Path, check: tuple[str, ...]
) -> None:
    """#582: ``schema_missing`` fails ``checks.schema``, not only the run."""
    rule = tide_corpus_repo / "Objects" / "Detection Rules" / "rule-0001-sentinel-kql.yaml"
    text = rule.read_text(encoding="utf-8")
    assert "  schema: rule::1.0\n" in text
    rule.write_text(text.replace("  schema: rule::1.0\n", ""), encoding="utf-8")
    result = invoke_cli("validate", "--file", rule.name, *check)
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["checks"]["schema"]["status"] == "failed"
    assert [(i["code"], i["field_path"]) for i in payload["report"]["issues"]] == [
        ("schema_missing", ["metadata", "schema"])
    ]


@pytest.mark.parametrize(
    ("schema", "message"),
    [
        ("rule::9.9", "unknown schema identifier: 'rule::9.9'"),
        ("threat::1.0", "'threat::1.0' is not a rule schema identifier"),
    ],
)
def test_validate_reports_an_unusable_schema_identifier_at_its_line(
    invoke_cli, tide_corpus_repo: Path, schema: str, message: str
) -> None:
    """#582: an unknown or other-type identifier fails at ``metadata.schema``."""
    rule = tide_corpus_repo / "Objects" / "Detection Rules" / "rule-0001-sentinel-kql.yaml"
    text = rule.read_text(encoding="utf-8")
    assert "  schema: rule::1.0\n" in text
    rule.write_text(
        text.replace("  schema: rule::1.0\n", f"  schema: {schema}\n"), encoding="utf-8"
    )
    result = invoke_cli("validate", "--file", rule.name)
    assert result.exit_code == 1, result.stdout + result.stderr
    (issue,) = parse_cli_json(result)["report"]["issues"]
    assert (issue["code"], issue["field_path"], issue["message"]) == (
        "schema_validation",
        ["metadata", "schema"],
        message,
    )
    lines = rule.read_text(encoding="utf-8").splitlines()
    assert lines[issue["yaml_line"]] == f"  schema: {schema}"


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
    """Bare ``validate query`` refuses and names ``--live``. It does not scan."""
    result = invoke_cli(
        "validate",
        "query",
        "--platform",
        platform,
        "--strategy",
        "PREVIEW",
        "--strategy",
        "RELEASE",
        "--wide",
    )
    # Without --live a supported platform is a usage error; an unsupported one fails.
    assert result.exit_code == (2 if expects_supported else 1), result.stdout + result.stderr
    if "{" in result.stdout:
        body = parse_cli_json(result)
        assert body.get("supported") is expects_supported
        assert body.get("status") == "failed"
        assert body.get("mode") != "offline-syntax"
        if expects_supported:
            assert "--live" in body.get("message", "")
        else:
            assert "not supported" in body.get("message", "")


def test_validate_query_without_strategy_or_wide(invoke_cli) -> None:
    """No ``--strategy`` must not traceback on validate query (issue #164)."""
    result = invoke_cli("validate", "query", "--platform", "sentinel")
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["failure"]["code"] == "usage_missing_option"
    assert payload["failure"]["argument"] == "--live"
    assert payload.get("supported") is True
    assert payload.get("status") == "failed"
    assert "--live" in payload["message"]


def test_validate_query_live_refuses_the_removed_deployment_plan(
    invoke_cli, refuse_deployment_engines: list[str]
) -> None:
    """``DEPLOYMENT_PLAN`` was removed in 0.17.0; a pipeline still setting it fails loudly."""
    result = invoke_cli(
        "validate",
        "query",
        "--platform",
        "sentinel",
        "--live",
        extra_env={"DEPLOYMENT_PLAN": "FULL"},
    )
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert payload["message"].startswith("DEPLOYMENT_PLAN was removed in 0.17.0")
    assert "Unset DEPLOYMENT_PLAN" in payload["message"]
    assert refuse_deployment_engines == []


def test_validate_query_bare_needs_no_vendor_sdk(invoke_cli) -> None:
    """A stock install has no azure package. The refusal must not import it."""
    with hidden_modules("azure"):
        result = invoke_cli("validate", "query", "--platform", "sentinel")
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert "--live" in payload["message"]
    assert "mode" not in payload


@pytest.fixture
def sentinel_tenant(tide_corpus_repo: Path) -> None:
    """``--live`` stops before the engine when no tenant is configured (#314)."""
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")


@pytest.mark.usefixtures("sentinel_tenant")
def test_validate_query_live_with_a_broken_sdk_advises_a_reinstall(invoke_cli) -> None:
    """--live is allowed to fail, but with advice instead of a traceback (#239)."""
    with hidden_modules("azure", purge=("opentide.platforms.sentinel",)):
        result = invoke_cli("validate", "query", "--platform", "sentinel", "--live", "--wide")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["mode"] == "live"
    assert payload["status"] == "failed"
    assert payload["advice"] == "reinstall opentide: pip install --force-reinstall opentide"


@pytest.mark.usefixtures("sentinel_tenant")
def test_validate_query_live_uses_the_platform_engine(invoke_cli, mock_query_validators) -> None:
    result = invoke_cli("validate", "query", "--platform", "sentinel", "--live", "--wide")
    payload = assert_json_ok(result)
    assert payload["mode"] == "live"
    assert payload["status"] == "passed"
    assert payload["strategies"] == ["PREVIEW", "RELEASE"]
    assert "plan" not in payload


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
