"""A Bitdefender block compiled to GravityZone JSON-RPC bodies: goldens and derivations."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.bitdefender.compile import (
    APOSTROPHE,
    ELLIPSIS,
    LEFT_ANGLE,
    QUOTE,
    RIGHT_ANGLE,
    BitdefenderTargetError,
    compile_rule,
    create_params,
    delete_params,
    derive_description,
    normalise,
    request_body,
    update_params,
)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bitdefender"
RULE_ID = "6372b7a3897aaa77ee021642"

#: golden → (source rule, method, strategy), as the specification derives them.
GOLDENS = {
    "rule-bitdefender-detection-1.0.create.api.json": (
        "rule-bitdefender-detection-1.0.yaml",
        "createCustomRule",
        StatusStrategy.RELEASE,
    ),
    "rule-bitdefender-detection-1.0.update.api.json": (
        "rule-bitdefender-detection-1.0.yaml",
        "updateCustomRule",
        StatusStrategy.RELEASE,
    ),
    "rule-bitdefender-detection-1.0.disable.api.json": (
        "rule-bitdefender-detection-1.0.yaml",
        "updateCustomRule",
        StatusStrategy.DISABLEMENT,
    ),
    "rule-bitdefender-yara-1.0.create.api.json": (
        "rule-bitdefender-yara-1.0.yaml",
        "createCustomRule",
        StatusStrategy.RELEASE,
    ),
}


def _setup(**overrides: Any) -> SimpleNamespace:
    document = tomllib.loads((FIXTURES / "tenant.toml").read_text(encoding="utf-8"))
    return SimpleNamespace(**{**document["tenants"][0]["setup"], **overrides})


def _rule(name: str) -> DetectionRule:
    return load_rule_from_dict(yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8")))


def _block_rule(block: dict[str, Any], **rule: Any) -> DetectionRule:
    document: dict[str, Any] = {
        "name": "Encoded PowerShell",
        "metadata": {
            "uuid": "11111111-2222-4333-8444-555555555555",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-11-10",
            "modified": "2026-11-10",
            "tlp": "clear",
        },
        "description": "PowerShell\n  started.",
        "configurations": {
            "bitdefender": {
                "status": "STAGING",
                "detection": {
                    "target": "process",
                    "criteria": [{"field": "Process.Name", "is": "powershell.exe"}],
                },
                **block,
            }
        },
        **rule,
    }
    return load_rule_from_dict(document)


@pytest.mark.parametrize("golden", sorted(GOLDENS))
def test_bodies_match_the_specification_goldens(golden: str) -> None:
    source, method, strategy = GOLDENS[golden]
    compiled = compile_rule(_rule(source), strategy, _setup())
    params = (
        create_params(compiled)
        if method == "createCustomRule"
        else update_params(compiled, RULE_ID)
    )
    expected = json.loads((FIXTURES / golden).read_text(encoding="utf-8"))
    assert request_body(method, params) == expected


def test_every_update_carries_the_whole_payload() -> None:
    params = update_params(
        compile_rule(_rule(next(iter(GOLDENS.values()))[0]), StatusStrategy.RELEASE, _setup()),
        RULE_ID,
    )
    assert set(params) == {"ruleId", "type", "name", "description", "tags", "settings", "targets"}
    assert [entry["type"] for entry in params["settings"]["automaticActions"]] == [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
    ]


def test_delete_names_the_rule_and_a_detection_type() -> None:
    assert request_body("deleteCustomRule", delete_params(RULE_ID)) == {
        "jsonrpc": "2.0",
        "method": "deleteCustomRule",
        "params": {"ruleId": RULE_ID, "type": 1},
    }


def test_text_is_normalised() -> None:
    assert (
        normalise("  <a> 'b' \"c\"")
        == f"{LEFT_ANGLE}a{RIGHT_ANGLE} {APOSTROPHE}b{APOSTROPHE} {QUOTE}c{QUOTE}"
    )
    long = derive_description("word " * 400)
    assert len(long) == 1024 and long.endswith(f"{ELLIPSIS}")
    assert derive_description("a\n   b\t c ") == "a b c"


@pytest.mark.parametrize(
    ("block", "response", "severity"),
    [
        ({"severity": "Low"}, {"alert_severity": "Critical"}, 1),
        ({}, {"alert_severity": "Critical"}, 3),
        ({}, {"alert_severity": "High"}, 3),
        ({}, {"alert_severity": "Medium"}, 2),
        ({}, {"alert_severity": "Low"}, 1),
        ({}, {"alert_severity": "Informational"}, 1),
        ({}, None, 2),
    ],
)
def test_severity(block: dict[str, Any], response: dict[str, Any] | None, severity: int) -> None:
    extra = {"response": response} if response is not None else {}
    compiled = compile_rule(_block_rule(block, **extra), StatusStrategy.RELEASE)
    assert compiled.settings["severity"] == severity


def test_tags_are_normalised_unique_and_at_least_two_characters() -> None:
    rule = _block_rule({"tags": ["x", "office", "<tag>", "office", "y" * 200]})
    compiled = compile_rule(rule, StatusStrategy.RELEASE, _setup(tags=["office", "tenant"]))
    assert compiled.tags == [
        "office",
        f"{LEFT_ANGLE}tag{RIGHT_ANGLE}",
        "y" * 128,
        "opentide",
        "opentide:11111111-2222-4333-8444-555555555555",
        "tenant",
    ]


def test_shared_name_wins_and_alert_is_a_filter() -> None:
    rule = _block_rule(
        {
            "name": " 'Quoted' name",
            "detection": {
                "target": "process",
                "criteria": [{"field": "Process.Name", "is": "x.exe"}],
                "alert": "Suspicious process",
            },
        }
    )
    compiled = compile_rule(rule, StatusStrategy.RELEASE)
    assert compiled.name == f"{APOSTROPHE}Quoted{APOSTROPHE} name"
    assert compiled.settings["filters"] == [{"field": "detection", "value": "Suspicious process"}]


def test_yara_query_has_lf_endings_and_one_trailing_newline() -> None:
    rule = _block_rule(
        {
            "detection": None,
            "yara": {"signature": "rule A {\r\n condition: true\r\n}", "on_access": True},
        }
    )
    settings = compile_rule(rule, StatusStrategy.RELEASE).settings
    assert settings["yaraQuery"] == "rule A {\n condition: true\n}\n"
    assert settings["status"] == 1
    disabled = compile_rule(rule, StatusStrategy.DISABLEMENT).settings
    assert disabled["status"] == 0


def test_tenant_without_automatic_actions_omits_them() -> None:
    rule = _block_rule({"actions": {"isolate": True}})
    compiled = compile_rule(rule, StatusStrategy.RELEASE, _setup(automatic_actions=False))
    assert "automaticActions" not in compiled.settings


def test_tenant_targets_companies_and_partner_company() -> None:
    company = "61827b8036492c2fc0718722"
    setup = _setup(
        targets={"companies": ["acme"]},
        companies={"acme": company},
        company_id="5b680f6fb1a43d860a7b23c8",
    )
    params = create_params(compile_rule(_block_rule({}), StatusStrategy.RELEASE, setup))
    assert params["targets"] == {"companiesIds": [company]}
    assert params["companyId"] == "5b680f6fb1a43d860a7b23c8"
    assert list(params)[-1] == "returnRuleId"


def test_no_targets_means_the_whole_company() -> None:
    params = create_params(
        compile_rule(_block_rule({}), StatusStrategy.RELEASE, _setup(endpoint_tags={}))
    )
    assert "targets" not in params


def test_an_unknown_target_alias_fails_before_any_call() -> None:
    rule = _block_rule({"targets": {"endpoint_tags": ["nowhere"]}})
    with pytest.raises(BitdefenderTargetError, match="bitdefender_target_unknown"):
        compile_rule(rule, StatusStrategy.RELEASE, _setup())
    rule = _block_rule({"targets": {"companies": ["nowhere"]}})
    with pytest.raises(BitdefenderTargetError, match="bitdefender_target_unknown"):
        compile_rule(rule, StatusStrategy.RELEASE, _setup())
