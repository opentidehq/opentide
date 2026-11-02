"""SysdigConfig and its constraint codes (sysdig-1.0, Constraints)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.loading.platform_loader import load_platform_config
from opentide.models.platform import PLATFORM_CONFIG_MODELS, RuleConfigurations, SysdigConfig

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sysdig"
RULE = {"status": "STAGING", "condition": "spawned_process and container"}
TUNING = {"status": "STAGING", "append_to_rule": "Terminal shell in container"}


def _codes(block: dict[str, Any]) -> str:
    with pytest.raises(ValidationError) as caught:
        SysdigConfig.model_validate(block)
    return str(caught.value)


def test_sysdig_is_a_registered_platform() -> None:
    assert PLATFORM_CONFIG_MODELS["sysdig"] is SysdigConfig
    assert SysdigConfig.schema_identifier() == "platform::sysdig::1.0"
    assert "sysdig" in RuleConfigurations.model_fields


@pytest.mark.parametrize(
    "path",
    sorted(FIXTURES.glob("*.yaml")) + sorted((FIXTURES / "public").glob("*.yaml")),
    ids=lambda p: p.name,
)
def test_fixture_blocks_validate(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(document, list):  # a generated rules file, not a rule
        return
    block = document["configurations"]["sysdig"]
    assert isinstance(load_platform_config("sysdig", block), SysdigConfig)


def test_the_specification_invalid_fixture_reports_both_codes() -> None:
    block = {
        **TUNING,
        "condition": "and not proc.pname = sshd",
        "output": "Shell spawned",
        "priority": "ERROR",
        "exceptions": [
            {"name": "misaligned", "fields": ["proc.name", "proc.pname"], "comps": ["="]}
        ],
    }
    message = _codes(block)
    assert "sysdig_tuning_keys" in message
    assert "sysdig_exception_shape" in message


def test_omitted_status_is_the_missing_field_not_a_code() -> None:
    with pytest.raises(ValidationError) as caught:
        SysdigConfig.model_validate({"condition": "x"})
    assert [e["loc"] for e in caught.value.errors()] == [("status",)]


@pytest.mark.parametrize(
    ("code", "block"),
    [
        ("sysdig_rule_shape", {"status": "STAGING"}),
        ("sysdig_rule_shape", {"status": "STAGING", "condition": "   "}),
        ("sysdig_rule_shape", TUNING),
        ("sysdig_rule_shape", {**TUNING, "exceptions": []}),
        ("sysdig_rule_shape", {**TUNING, "append_to_rule": " ", "condition": "and x"}),
        ("sysdig_tuning_keys", {**TUNING, "condition": "and x", "source": "syscall"}),
        ("sysdig_tuning_keys", {**TUNING, "condition": "and x", "policies": ["p"]}),
        ("sysdig_tuning_keys", {**TUNING, "condition": "and x", "name": "Renamed"}),
        ("sysdig_priority", {**RULE, "priority": "SEVERE"}),
        ("sysdig_source", {**RULE, "source": "K8s-Audit"}),
        ("sysdig_exception_shape", {**RULE, "exceptions": [{"name": "", "fields": "a"}]}),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": "a"}, {"name": "e", "fields": "b"}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": "a", "comps": "="}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": "a", "values": [["x"]]}]},
        ),
        ("sysdig_exception_shape", {**RULE, "exceptions": [{"name": "e", "fields": ["a", "a"]}]}),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": ["a", "b"], "values": [["x"]]}]},
        ),
        (
            "sysdig_exception_shape",
            {
                **RULE,
                "exceptions": [
                    {
                        "name": "e",
                        "fields": ["a", "b"],
                        "comps": ["=", "in"],
                        "values": [["x", "y"]],
                    }
                ],
            },
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": ["a"], "comps": ["like"]}]},
        ),
        ("sysdig_definition_name", {**RULE, "lists": [{"name": "my-list", "items": ["a"]}]}),
        ("sysdig_definition_name", {**RULE, "macros": [{"name": "and", "condition": "x"}]}),
        (
            "sysdig_definition_duplicate",
            {
                **RULE,
                "macros": [{"name": "dup", "condition": "x"}],
                "lists": [{"name": "dup", "items": ["a"]}],
            },
        ),
        (
            "sysdig_definition_cycle",
            {
                **RULE,
                "condition": "loop_a",
                "macros": [
                    {"name": "loop_a", "condition": "loop_b"},
                    {"name": "loop_b", "condition": "loop_a and x"},
                ],
            },
        ),
    ],
)
def test_each_constraint_reports_its_code(code: str, block: dict[str, Any]) -> None:
    assert code in _codes(block)


@pytest.mark.parametrize(
    "block",
    [
        {**RULE, "priority": "info"},
        {**RULE, "priority": "Informational"},
        {**RULE, "source": "k8s_audit"},
        {**TUNING, "exceptions": [{"name": "e", "fields": "proc.name", "values": ["a", "b"]}]},
        {**TUNING, "condition": "and not proc.pname = x"},
        {
            **RULE,
            "exceptions": [
                {
                    "name": "e",
                    "fields": ["proc.name", "fd.name"],
                    "comps": ["=", "pmatch"],
                    "values": [["bash", ["/etc", "/tmp"]]],
                }
            ],
        },
        {**RULE, "exceptions": [{"name": "values_later", "fields": ["proc.name"]}]},
    ],
)
def test_valid_blocks_pass(block: dict[str, Any]) -> None:
    SysdigConfig.model_validate(block)


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError, match=r"extra_forbidden|Extra inputs"):
        SysdigConfig.model_validate({**RULE, "override": {"condition": "append"}})


def test_legacy_external_id_keys_are_dropped_by_the_loader_only() -> None:
    block = {**RULE, "rule_id_bundle": {"tenant": 1}}
    with pytest.raises(ValidationError):
        SysdigConfig.model_validate(block)
    assert isinstance(load_platform_config("sysdig", block), SysdigConfig)
