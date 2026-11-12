"""Exabeam tenant setup, workspace name checks and advisories (exabeam-1.0)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from opentide.core.io import load_toml
from opentide.models.configuration.platforms import (
    PLATFORM_CONFIGURATION_MODELS,
    ExabeamConfiguration,
)
from opentide.platforms.config import build_system_config
from opentide.platforms.exabeam.advisories import exabeam_advisories
from opentide.validation.exabeam_advisories import exabeam_advisory_issues
from opentide.validation.exabeam_names import exabeam_name_issues

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

BUNDLED = Path(__file__).resolve().parents[2] / "src/opentide/data/configurations/platforms"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exabeam"


def _config(setup: dict[str, Any]) -> Any:
    raw = {"platform": {"enabled": True}, "tenants": [{"name": "exa", "setup": setup}]}
    return build_system_config("exabeam", raw)


def _setup(**keys: Any) -> dict[str, Any]:
    return {"region": "eu", "client_id": "$EXA_ID", "client_secret": "${EXA_SECRET}", **keys}


def test_the_bundled_file_is_off_and_has_no_tenant() -> None:
    raw = load_toml(BUNDLED / "exabeam.toml")
    assert raw["platform"]["enabled"] is False
    assert raw["platform"]["name"] == "Exabeam New-Scale SIEM"
    assert "tenants" not in raw
    assert build_system_config("exabeam", raw).tenants is None


def test_the_specification_tenant_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXABEAM_CLIENT_ID", "resolved-id")
    monkeypatch.setenv("EXABEAM_CLIENT_SECRET", "resolved-secret")
    raw = tomllib.loads((FIXTURES / "tenant.toml").read_text(encoding="utf-8"))
    # The fixture's [platform] table carries identifier, subschema and flags, which
    # opentide's shared platform identity does not take on any platform.
    for key in ("identifier", "subschema", "flags"):
        del raw["platform"][key]
    (tenant,) = build_system_config("exabeam", raw).tenants
    assert tenant.setup.client_id == "resolved-id"
    assert tenant.setup.client_secret == "resolved-secret"
    assert tenant.setup.test_mode is False
    assert tenant.setup.url == "https://api.eu.exabeam.cloud"
    assert PLATFORM_CONFIGURATION_MODELS["exabeam"] is ExabeamConfiguration
    ExabeamConfiguration.model_validate(raw)


def test_defaults_and_api_url() -> None:
    (tenant,) = _config(_setup()).tenants
    assert tenant.setup.test_mode is False
    assert tenant.setup.api_url is None
    (gateway,) = _config(_setup(api_url="https://gw.example/exabeam/", test_mode=True)).tenants
    assert gateway.setup.url == "https://gw.example/exabeam"
    assert gateway.setup.test_mode is True


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ({"client_id": "$A", "client_secret": "$B"}, "missing required key\\(s\\): region"),
        (_setup(client_secret=None), "missing required key\\(s\\): client_secret"),
        (_setup(region="use1"), "region 'use1' is not an Exabeam API region"),
        (_setup(client_id="literal"), "client_id must be an environment variable"),
        (_setup(client_secret="hunter2"), "client_secret must be an environment variable"),
        (_setup(url="https://x"), "unknown key\\(s\\): url"),
        (_setup(api_url="http://gw.example"), "api_url must be an https:// base URL"),
        (_setup(test_mode="yes"), "test_mode must be true or false"),
    ],
)
def test_a_bad_tenant_fails_configuration_load(setup: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _config({key: value for key, value in setup.items() if value is not None})


# --- names across the workspace --------------------------------------------------------


def _body(name: str, *, block_name: str | None = None, enabled: bool = True) -> dict[str, Any]:
    block: dict[str, Any] = {"enabled": enabled, "status": "STAGING"}
    if block_name is not None:
        block["name"] = block_name
    return {"name": name, "configurations": {"exabeam": block}}


def _issues(rules: dict[str, dict[str, Any]], *scope: str) -> list[tuple[str, str]]:
    found = exabeam_name_issues(rules, scope or tuple(rules), lambda uuid: None)
    return [(issue.object_uuid, issue.code) for issue in found]


def test_two_enabled_blocks_with_one_name_fail_case_insensitively() -> None:
    rules = {"a": _body("Spray"), "b": _body("other", block_name="SPRAY"), "c": _body("Lone")}
    assert _issues(rules) == [("a", "exabeam_name_duplicate"), ("b", "exabeam_name_duplicate")]
    # Only the rules in scope are reported, against every rule of the workspace.
    assert _issues(rules, "a") == [("a", "exabeam_name_duplicate")]


def test_a_disabled_block_does_not_take_its_name() -> None:
    rules = {"a": _body("Spray"), "b": _body("Spray", enabled=False)}
    assert _issues(rules) == []


def test_a_rule_name_longer_than_128_without_a_block_name_fails() -> None:
    rules = {
        "a": _body("x" * 129),
        "b": _body("x" * 129, block_name="short"),
        "c": _body("x" * 128),
    }
    assert _issues(rules) == [("a", "exabeam_name_length")]


def test_a_rule_without_an_exabeam_block_is_skipped() -> None:
    assert _issues({"a": {"name": "x"}, "b": {"name": "y", "configurations": None}}) == []


# --- advisories ------------------------------------------------------------------------


def _advisory_codes(**block: Any) -> list[str]:
    return [item.code for item in exabeam_advisories({"configurations": {"exabeam": block}})]


def test_outcome_none_without_email_is_silent() -> None:
    assert _advisory_codes(outcome="none") == ["exabeam_outcome_silent"]
    assert _advisory_codes(outcome="none", email={"recipients": ["a@b.io"]}) == []
    assert _advisory_codes(outcome="case") == []


def test_a_correlation_window_shorter_than_a_sequence_window() -> None:
    sequences = [
        {"query": "a", "threshold": {"within": "1h"}},
        {"query": "b", "threshold": {"within": "30m"}},
        {"query": "c"},
    ]
    assert _advisory_codes(sequences=sequences, correlation={"within": "45m"}) == [
        "exabeam_correlation_window"
    ]
    assert _advisory_codes(sequences=sequences, correlation={"within": "1h"}) == []
    assert _advisory_codes(sequences=sequences, correlation={"within": "1d"}) == []
    assert _advisory_codes(sequences=sequences, correlation={"within": "bad"}) == []


def test_the_specification_fixtures_earn_no_advisory() -> None:
    for name in ("rule-exabeam-threshold-1.0.yaml", "rule-exabeam-sequence-1.0.yaml"):
        body = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
        assert exabeam_advisories(body) == []
    assert exabeam_advisories({"configurations": None}) == []


def test_advisories_are_validate_warnings_on_rules_only() -> None:
    body = {"configurations": {"exabeam": {"outcome": "none"}}}
    (issue,) = exabeam_advisory_issues(body, object_uuid="u", object_type="rule", file_path=None)
    assert (issue.code, issue.severity) == ("exabeam_outcome_silent", "warning")
    assert issue.field_path == ("configurations", "exabeam", "outcome")
    assert (
        exabeam_advisory_issues(body, object_uuid="u", object_type="threat", file_path=None) == []
    )
