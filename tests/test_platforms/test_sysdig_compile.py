"""A Sysdig block compiled to a Falco rule: goldens and derivations (sysdig-1.0)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.sysdig.compile import api_body, compile_rule
from opentide.platforms.sysdig.generate import rules_file

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sysdig"
PUBLIC = sorted((FIXTURES / "public").glob("*.yaml"))


def _rule(name: str) -> DetectionRule:
    return load_rule_from_dict(yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8")))


def _block_rule(block: dict[str, Any], **rule: Any) -> DetectionRule:
    document: dict[str, Any] = {
        "name": "Shell in container",
        "metadata": {
            "uuid": "11111111-2222-4333-8444-555555555555",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-11-02",
            "modified": "2026-11-02",
            "tlp": "clear",
        },
        "description": "A shell\n  started.",
        "configurations": {"sysdig": {"status": "STAGING", **block}},
        **rule,
    }
    return load_rule_from_dict(document)


def test_new_rule_matches_the_specification_rules_file() -> None:
    compiled = compile_rule(_rule("rule-sysdig-1.0.yaml"), StatusStrategy.PREVIEW)
    expected = (FIXTURES / "rule-sysdig-1.0.falco.yaml").read_bytes()
    assert rules_file(compiled).encode("utf-8") == expected


def test_new_rule_matches_the_specification_api_body() -> None:
    compiled = compile_rule(_rule("rule-sysdig-1.0.yaml"), StatusStrategy.PREVIEW)
    expected = json.loads((FIXTURES / "rule-sysdig-1.0.api.json").read_text(encoding="utf-8"))
    assert api_body(compiled) == expected


def test_tuning_matches_the_specification_rules_file() -> None:
    compiled = compile_rule(_rule("rule-sysdig-tuning-1.0.yaml"), StatusStrategy.RELEASE)
    expected = (FIXTURES / "rule-sysdig-tuning-1.0.falco.yaml").read_bytes()
    assert rules_file(compiled).encode("utf-8") == expected


def test_tuning_api_body_appends_only_condition_and_exceptions() -> None:
    compiled = compile_rule(_rule("rule-sysdig-tuning-1.0.yaml"), StatusStrategy.RELEASE)
    assert api_body(compiled) == {
        "name": "Terminal shell in container",
        "description": "",
        "tags": [],
        "details": {
            "ruleType": "FALCO",
            "append": True,
            "condition": {
                "condition": "and not proc.pname in (gitlab-runner, buildkite-agent)",
                "components": [],
            },
            "exceptions": [
                {
                    "name": "build_namespaces",
                    "fields": "k8s.ns.name",
                    "comps": "in",
                    "values": ["ci", "builds"],
                }
            ],
        },
    }


@pytest.mark.parametrize(
    ("severity", "priority", "api"),
    [
        ("Critical", "CRITICAL", "critical"),
        ("High", "ERROR", "error"),
        ("Medium", "WARNING", "warning"),
        ("Low", "NOTICE", "notice"),
        ("Informational", "INFORMATIONAL", "info"),
    ],
)
def test_priority_is_derived_from_alert_severity(severity: str, priority: str, api: str) -> None:
    rule = _block_rule({"condition": "x"}, response={"alert_severity": severity})
    compiled = compile_rule(rule, StatusStrategy.PREVIEW)
    assert compiled.priority == priority
    assert api_body(compiled)["details"]["priority"] == api


def test_a_rule_without_response_is_warning() -> None:
    assert (
        compile_rule(_block_rule({"condition": "x"}), StatusStrategy.PREVIEW).priority == "WARNING"
    )


@pytest.mark.parametrize(("written", "priority"), [("info", "INFORMATIONAL"), ("Error", "ERROR")])
def test_an_authored_priority_wins(written: str, priority: str) -> None:
    rule = _block_rule(
        {"condition": "x", "priority": written}, response={"alert_severity": "Critical"}
    )
    assert compile_rule(rule, StatusStrategy.PREVIEW).priority == priority


@pytest.mark.parametrize(
    ("source", "tail"),
    [
        ("syscall", " | evt_type=%evt.type user=%user.name"),
        ("k8s_audit", " | user=%ka.user.name verb=%ka.verb"),
        ("aws_cloudtrail", " | user=%ct.user region=%ct.region"),
    ],
)
def test_default_output_follows_the_source(source: str, tail: str) -> None:
    rule = _block_rule({"condition": "x", "source": source})
    assert compile_rule(rule, StatusStrategy.PREVIEW).output.startswith("Shell in container" + tail)


def test_default_output_of_another_source_is_the_rule_name() -> None:
    rule = _block_rule({"condition": "x", "source": "okta", "name": "Okta MFA reset"})
    compiled = compile_rule(rule, StatusStrategy.PREVIEW)
    assert (compiled.name, compiled.output, compiled.source) == (
        "Okta MFA reset",
        "Okta MFA reset",
        "okta",
    )


@pytest.mark.parametrize(
    ("strategy", "maturity"),
    [
        (StatusStrategy.RELEASE, "maturity_stable"),
        (StatusStrategy.PREVIEW, "maturity_incubating"),
        (StatusStrategy.UNIVERSAL, "maturity_sandbox"),
        (StatusStrategy.DISABLEMENT, "maturity_sandbox"),
    ],
)
def test_tags_are_block_attack_maturity_then_tenant(
    strategy: StatusStrategy, maturity: str
) -> None:
    rule = _block_rule(
        {"condition": "x", "tags": ["container", "T1078"]}, techniques=["T1078", "T1609"]
    )
    compiled = compile_rule(rule, strategy, tenant_tags=["soc", "container"])
    assert compiled.tags == [
        "container",
        "T1078",
        "T1609",
        "mitre_initial_access",
        "mitre_execution",
        "mitre_persistence",
        "mitre_privilege_escalation",
        "mitre_stealth",
        maturity,
        "soc",
    ]


def test_disablement_writes_enabled_false() -> None:
    compiled = compile_rule(_block_rule({"condition": "x"}), StatusStrategy.DISABLEMENT)
    assert compiled.enabled is False
    assert "  enabled: false\n" in rules_file(compiled)


def test_description_whitespace_is_collapsed() -> None:
    assert compile_rule(_block_rule({"condition": "x"}), StatusStrategy.PREVIEW).desc == (
        "A shell started."
    )


def test_required_versions_lead_the_rules_file() -> None:
    rule = _block_rule(
        {
            "condition": "ka.verb = create",
            "source": "k8s_audit",
            "required_engine_version": "0.39.0",
            "required_plugin_versions": [{"name": "k8saudit", "version": "0.7.0"}],
        }
    )
    items = yaml.safe_load(rules_file(compile_rule(rule, StatusStrategy.PREVIEW)))
    assert items[0] == {"required_engine_version": "0.39.0"}
    assert items[1] == {"required_plugin_versions": [{"name": "k8saudit", "version": "0.7.0"}]}
    assert items[2]["rule"] == "Shell in container"


def test_yaml_sensitive_values_survive_the_rules_file() -> None:
    rule = _block_rule(
        {
            "condition": 'proc.name = "yes: no" and fd.name startswith /tmp',
            "exceptions": [
                {
                    "name": "e",
                    "fields": ["proc.name", "x.y"],
                    "comps": ["=", "!="],
                    "values": [["no", "1.0"]],
                }
            ],
            "tags": ["yes", "on"],
        },
        description="Colon: a # hash and 'quotes'",
    )
    compiled = compile_rule(rule, StatusStrategy.PREVIEW)
    (item,) = yaml.safe_load(rules_file(compiled))
    assert item["condition"] == compiled.condition
    assert item["desc"] == "Colon: a # hash and 'quotes'"
    assert item["exceptions"][0]["comps"] == ["=", "!="]
    assert item["exceptions"][0]["values"] == [["no", "1.0"]]
    assert item["tags"][:2] == ["yes", "on"]


@pytest.mark.parametrize("path", PUBLIC, ids=lambda p: p.stem)
def test_public_falco_rules_compile_and_round_trip(path: Path) -> None:
    rule = load_rule_from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))
    compiled = compile_rule(rule, StatusStrategy.RELEASE)
    items = yaml.safe_load(rules_file(compiled))
    falco_rule = items[-1]
    assert falco_rule["rule"] == compiled.name
    if compiled.condition is not None:
        assert falco_rule["condition"] == compiled.condition
        assert "\n" not in compiled.condition
    body = api_body(compiled)
    assert body["details"]["ruleType"] == "FALCO"
    assert body["details"]["append"] is compiled.tuning


def _public(stem: str) -> DetectionRule:
    return load_rule_from_dict(
        yaml.safe_load((FIXTURES / "public" / f"{stem}.yaml").read_text(encoding="utf-8"))
    )


def test_public_search_keys_rule_expands_nested_macros_and_lists() -> None:
    compiled = compile_rule(_public("search-private-keys-or-passwords"), StatusStrategy.RELEASE)
    condition = compiled.condition or ""
    assert "grep_commands" not in condition
    assert "grep_more" not in condition
    assert "private_key_or_password" not in condition
    assert "(proc.name in (grep, egrep, fgrep))" in condition
    assert condition.startswith("spawned_process and ((((proc.name in (grep, egrep, fgrep)))")
    assert compiled.priority == "WARNING"
    assert compiled.tags[:5] == ["host", "container", "process", "filesystem", "T1552.001"]
    assert "mitre_credential_access" in compiled.tags


def test_public_k8s_rule_expands_its_list_and_keeps_tenant_macros() -> None:
    compiled = compile_rule(_public("k8s-attach-exec-pod"), StatusStrategy.PREVIEW)
    assert compiled.source == "k8s_audit"
    assert compiled.name == "Attach/Exec Pod"
    assert compiled.condition == (
        "kevt_started and pod_subresource and (kcreate or kget) and "
        "ka.target.subresource in (exec,attach) and not "
        "(ka.user.name in (oncall-admin, system:serviceaccount:ops:debugger))"
    )
    assert "%ka.uri.param[command]" in compiled.output


def test_public_cloudtrail_rule_keeps_json_field_arguments() -> None:
    compiled = compile_rule(_public("aws-console-login-without-mfa"), StatusStrategy.RELEASE)
    assert compiled.priority == "CRITICAL"
    assert 'json.value[/additionalEventData/MFAUsed]="No"' in (compiled.condition or "")
    assert compiled.tags[-1] == "maturity_stable"


def test_public_tuning_appends_with_an_override() -> None:
    compiled = compile_rule(_public("tuning-contact-k8s-api-server"), StatusStrategy.RELEASE)
    (item,) = yaml.safe_load(rules_file(compiled))
    assert item == {
        "rule": "Contact K8S API Server From Container",
        "condition": (
            "and not container.image.repository in "
            "(quay.io/prometheus/node-exporter, docker.io/grafana/agent)"
        ),
        "exceptions": [
            {
                "name": "monitoring_namespaces",
                "fields": ["k8s.ns.name", "proc.name"],
                "comps": ["in", "="],
                "values": [[["monitoring", "observability"], "node-exporter"]],
            }
        ],
        "override": {"condition": "append", "exceptions": "append"},
    }
