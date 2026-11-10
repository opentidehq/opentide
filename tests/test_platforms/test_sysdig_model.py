"""SysdigConfig and its constraint codes (sysdig-1.0, Constraints)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide._models.platform import PLATFORM_CONFIG_MODELS, RuleConfigurations, SysdigConfig
from opentide.loading.platform_loader import load_platform_config

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
            {**RULE, "exceptions": [{"name": "e", "fields": "a", "comps": "="}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": "a", "values": [["x"]]}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": ["a", "b"], "values": [["x"]]}]},
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
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": "a", "comps": ["in"]}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": "a", "comps": "exists"}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": ["a"], "comps": ["in oneof"]}]},
        ),
        (
            "sysdig_exception_shape",
            {
                **RULE,
                "exceptions": [{"name": "e", "fields": ["a"], "comps": ["startswith  anyof"]}],
            },
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": ["a"], "values": [[{"k": "v"}]]}]},
        ),
        (
            "sysdig_exception_shape",
            {**RULE, "exceptions": [{"name": "e", "fields": ["a"], "values": [[["x", ["y"]]]]}]},
        ),
        (
            "sysdig_definition_order",
            {
                **RULE,
                "condition": "loop_a",
                "macros": [
                    {"name": "loop_a", "condition": "loop_b"},
                    {"name": "loop_b", "condition": "x.y = 1"},
                ],
            },
        ),
        (
            "sysdig_definition_order",
            {**RULE, "macros": [{"name": "self", "condition": "self and x.y = 1"}]},
        ),
        (
            "sysdig_list_in_value",
            {
                **RULE,
                "lists": [{"name": "shells", "items": ["bash"]}],
                "exceptions": [{"name": "e", "fields": ["proc.name"], "values": [["shells"]]}],
            },
        ),
        (
            "sysdig_list_in_value",
            {
                **RULE,
                "lists": [{"name": "shells", "items": ["bash"]}],
                "exceptions": [{"name": "e", "fields": "proc.cmdline", "values": ["run shells"]}],
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


@pytest.mark.parametrize(
    "exceptions",
    [
        # what Falco's validate_exception_info accepts
        [{"name": "e", "fields": "a"}, {"name": "e", "fields": "b"}],  # a repeated name warns only
        [{"name": "e", "fields": ["a", "a"], "values": [["x", "y"]]}],  # repeated fields
        [{"name": "e", "fields": ["a", "b"], "comps": ["=", "in"], "values": [["x", "y"]]}],
        [
            {
                "name": "e",
                "fields": ["a", "b", "c"],
                "comps": ["exists", " startswith oneof ", "== allof"],
                "values": [["x", ["p", "q"], "z"]],
            }
        ],
        [{"name": "e", "fields": "a", "comps": "contains anyof", "values": ["x", "y"]}],
        [{"name": "e", "fields": "a", "comps": " pmatch ", "values": ["/tmp"]}],
        [
            {
                "name": "e",
                "fields": ["a"],
                "comps": ["<", ">=", "!=", "iglob", "bcontains", "regex"][:1],
                "values": [[1]],
            }
        ],
    ],
)
def test_exception_forms_falco_accepts_validate(exceptions: list[dict[str, Any]]) -> None:
    assert SysdigConfig.model_validate({**RULE, "exceptions": exceptions}).exceptions


@pytest.mark.parametrize(
    "lists",
    [
        [{"name": "l1", "items": ["l2", "bash"]}, {"name": "l2", "items": ["zsh"]}],
        [{"name": "l1", "items": ["bash", "l1"]}],  # an advisory, never an error
    ],
)
def test_list_order_is_never_a_model_error(lists: list[dict[str, Any]]) -> None:
    block = SysdigConfig.model_validate({**RULE, "condition": "proc.name in (l1)", "lists": lists})
    assert block.lists


def test_a_block_list_in_an_exception_value_validates_where_falco_expands_it() -> None:
    block = {
        **RULE,
        "lists": [{"name": "shells", "items": ["bash", "sh"]}],
        "exceptions": [
            {"name": "single", "fields": "proc.name", "values": ["shells", "zsh"]},
            {"name": "listop", "fields": ["proc.name"], "comps": ["in"], "values": [["shells"]]},
            {"name": "member", "fields": ["proc.name"], "comps": ["in"], "values": [[["shells"]]]},
        ],
    }
    assert SysdigConfig.model_validate(block).exceptions


@pytest.mark.parametrize("version", [0, 17, 35])
def test_minimum_engine_version_takes_a_non_negative_integer(version: int) -> None:
    block = SysdigConfig.model_validate({**RULE, "minimum_engine_version": version})
    assert block.minimum_engine_version == version


@pytest.mark.parametrize("version", ["17", "0.39.0", 0.37, -1, True])
def test_minimum_engine_version_rejects_anything_else(version: object) -> None:
    with pytest.raises(ValidationError, match="minimum_engine_version"):
        SysdigConfig.model_validate({**RULE, "minimum_engine_version": version})


@pytest.mark.parametrize("key", ["required_engine_version", "required_plugin_versions"])
def test_rules_file_keys_are_unknown(key: str) -> None:
    with pytest.raises(ValidationError, match=key):
        SysdigConfig.model_validate({**RULE, key: "0.39.0"})
