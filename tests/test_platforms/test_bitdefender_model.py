"""BitdefenderConfig and its constraint codes (bitdefender-1.0, Constraints; yara-1.0)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.loading.platform_loader import load_platform_config
from opentide.models.platform import PLATFORM_CONFIG_MODELS, BitdefenderConfig, RuleConfigurations
from opentide.validation.yara_signature import aliased_signatures

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bitdefender"
PROCESS = {"target": "process", "criteria": [{"field": "Process.Name", "is": "x.exe"}]}
YARA = {"signature": 'rule A {\n  strings:\n    $a = "evil"\n  condition:\n    $a\n}\n'}

#: The code each specification invalid fixture names in its header.
INVALID = {
    "rule-bitdefender-two-kinds.yaml": "bitdefender_rule_kind",
    "rule-bitdefender-criterion-field.yaml": "bitdefender_criterion_field",
    "rule-bitdefender-exclusion.yaml": "bitdefender_rule_kind",
    "rule-bitdefender-kill-on-yara.yaml": "bitdefender_action_scope",
}


def _block(**keys: Any) -> dict[str, Any]:
    return {"enabled": True, "schema": "platform::bitdefender::1.0", "status": "STAGING", **keys}


def _errors(block: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    """``(code, field_path)`` for each finding, as validate reports them."""
    with pytest.raises(ValidationError) as caught:
        BitdefenderConfig.model_validate(block)
    return [(error["type"], tuple(map(str, error["loc"]))) for error in caught.value.errors()]


def _codes(block: dict[str, Any]) -> set[str]:
    return {code for code, _ in _errors(block)}


def _detection(target: str, *criteria: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"target": target, "criteria": list(criteria), **extra}


def test_bitdefender_is_a_registered_platform() -> None:
    assert PLATFORM_CONFIG_MODELS["bitdefender"] is BitdefenderConfig
    assert BitdefenderConfig.schema_identifier() == "platform::bitdefender::1.0"
    assert "bitdefender" in RuleConfigurations.model_fields


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.yaml")))
def test_the_specification_fixtures_validate(name: str) -> None:
    document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    block = load_platform_config("bitdefender", document["configurations"]["bitdefender"])
    assert isinstance(block, BitdefenderConfig)


@pytest.mark.parametrize(("name", "code"), sorted(INVALID.items()))
def test_the_specification_invalid_fixtures_report_their_code(name: str, code: str) -> None:
    document = yaml.safe_load((FIXTURES / "invalid" / name).read_text(encoding="utf-8"))
    assert code in _codes(document["configurations"]["bitdefender"])


def test_a_minimal_block_validates() -> None:
    block = BitdefenderConfig.model_validate(_block(detection=PROCESS))
    assert block.kind == "detection"
    assert BitdefenderConfig.model_validate(_block(yara=YARA)).kind == "yara"


def test_omitted_status_is_the_missing_field_not_a_code() -> None:
    with pytest.raises(ValidationError) as caught:
        BitdefenderConfig.model_validate({"detection": PROCESS})
    assert [e["loc"] for e in caught.value.errors()] == [("status",)]


@pytest.mark.parametrize(
    ("code", "block"),
    [
        ("bitdefender_rule_kind", _block()),
        ("bitdefender_rule_kind", _block(detection=PROCESS, yara=YARA)),
        ("bitdefender_rule_kind", _block(exclusion=PROCESS)),
        ("bitdefender_target", _block(detection={**PROCESS, "target": "flow"})),
        ("bitdefender_target", _block(detection={**PROCESS, "target": "bitbucket repository"})),
        ("bitdefender_target", _block(detection={**PROCESS, "target": "Process"})),
        (
            "bitdefender_criterion_shape",
            _block(
                detection=_detection("process", {"field": "Process.Name", "is": "a", "any": ["b"]})
            ),
        ),
        (
            "bitdefender_criterion_shape",
            _block(detection=_detection("process", {"field": "Process.Name"})),
        ),
        (
            "bitdefender_criterion_shape",
            _block(detection=_detection("process", {"field": "Process.Name", "any": []})),
        ),
        (
            "bitdefender_criterion_shape",
            _block(detection=_detection("process", {"field": "Process.Name", "is": ["a"]})),
        ),
        (
            "bitdefender_criterion_shape",
            _block(detection=_detection("process", {"field": "Process.Name", "contains": 4})),
        ),
        (
            "bitdefender_criterion_field",
            _block(detection=_detection("process", {"field": "File.Name", "is": "a"})),
        ),
        (
            "bitdefender_criterion_relation",
            _block(detection=_detection("process", {"field": "Process.MD5", "contains": "*a*"})),
        ),
        (
            "bitdefender_criterion_relation",
            _block(
                detection=_detection("registry", {"field": "Registry.Operation", "contains": "k*"})
            ),
        ),
        (
            "bitdefender_criterion_value",
            _block(detection=_detection("registry", {"field": "Registry.DataType", "is": "float"})),
        ),
        (
            "bitdefender_criterion_value",
            _block(
                detection=_detection(
                    "connection", {"field": "Connection.DestinationPort", "any": [443, 70000]}
                )
            ),
        ),
        (
            "bitdefender_criterion_value",
            _block(
                detection=_detection("connection", {"field": "Connection.SourcePort", "is": "443"})
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "file",
                    {"field": "File.MD5", "is": "44d88612fea8a8f36de82e1278abb02f"},
                    {"field": "File.CreatedBy.Name", "is": "a.exe"},
                )
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "file", {"field": "File.Operation", "any": ["rename", "downloaded"]}
                )
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "file", {"field": "File.CertificateSignedStatus", "is": "is_unsigned"}
                )
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection("connection", {"field": "Connection.Protocol", "is": "smb"})
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "file",
                    {"field": "File.Operation", "is": "downloaded"},
                    alert="Suspicious download",
                )
            ),
        ),
        (
            "bitdefender_action_scope",
            _block(
                detection=_detection(
                    "connection",
                    {"field": "Connection.Domain", "is": "x"},
                    {"field": "Connection.Protocol", "is": "smb"},
                ),
                actions={"kill_process": True},
            ),
        ),
        (
            "bitdefender_action_scope",
            _block(
                detection=_detection("registry", {"field": "Registry.Key", "is": "HKLM\\x"}),
                actions={"quarantine": True},
            ),
        ),
        ("bitdefender_action_scope", _block(yara=YARA, actions={"kill_process": True})),
        (
            "bitdefender_targets_shape",
            _block(detection=PROCESS, targets={"endpoint_tags": ["a"], "companies": ["b"]}),
        ),
        ("bitdefender_targets_shape", _block(detection=PROCESS, targets={"companies": []})),
        ("bitdefender_severity", _block(detection=PROCESS, severity="Critical")),
        ("bitdefender_severity", _block(detection=PROCESS, severity="high")),
        ("bitdefender_yara_ascii", _block(yara={"signature": YARA["signature"] + "// é\n"})),
        (
            "bitdefender_yara_size",
            _block(yara={"signature": YARA["signature"] + "//" + "x" * 30_000 + "\n"}),
        ),
        ("yara_include", _block(yara={"signature": 'include "other.yar"\n' + YARA["signature"]})),
        ("yara_empty_signature", _block(yara={"signature": "   "})),
        ("yara_empty_signature", _block(yara={"signature": 'import "pe"\n'})),
        (
            "yara_empty_signature",
            _block(yara={"signature": "private rule A { condition: true }\n"}),
        ),
        (
            "yara_duplicate_rule",
            _block(yara={"signature": YARA["signature"] + "rule A { condition: true }\n"}),
        ),
    ],
)
def test_each_constraint_reports_its_code(code: str, block: dict[str, Any]) -> None:
    assert _codes(block) == {code}


@pytest.mark.parametrize(
    "detection",
    [
        _detection("process", {"field": "Process.CommandLine", "contains": "*-enc*"}),
        _detection("file", {"field": "File.Operation", "any": ["rename", "write"]}),
        _detection(
            "file",
            {"field": "File.Name", "is": "a.exe"},
            {"field": "File.CertificateSignedStatus", "is": "is_unsigned"},
        ),
        _detection(
            "connection",
            {"field": "Connection.Domain", "contains": "*.example"},
            {"field": "Connection.Protocol", "is": "http/https"},
            {"field": "Connection.DestinationPort", "any": [80, 443]},
        ),
        _detection("email", {"field": "Email.Sender", "is": "x@example.com"}, alert="Phishing"),
        _detection(
            "connection",
            {"field": "Connection.Email.Subject", "contains": "*invoice*"},
            {"field": "Connection.Email.Operation", "is": "received"},
        ),
        _detection("connection", {"field": "Connection.SourceUser", "is": "alice"}, alert="x"),
        _detection(
            "connection",
            {"field": "Connection.Bucket.Name", "is": "backups"},
            {"field": "Connection.Bucket.Operation", "any": ["deleted", "download"]},
        ),
        _detection("file", {"field": "File.Operation", "is": "downloaded"}),
        _detection("file", {"field": "File.Name", "is": "a.exe"}, alert="Suspicious download"),
    ],
)
def test_catalogue_conforming_detections_validate(detection: dict[str, Any]) -> None:
    BitdefenderConfig.model_validate(_block(detection=detection))


def test_process_actions_follow_a_created_by_criterion() -> None:
    detection = _detection("registry", {"field": "Registry.CreatedBy.Name", "is": "reg.exe"})
    actions = {"kill_process": {"include_parent": True}, "quarantine": True, "sandbox": True}
    block = BitdefenderConfig.model_validate(_block(detection=detection, actions=actions))
    assert block.actions is not None


def test_yara_keywords_in_comments_and_strings_are_not_rules() -> None:
    signature = (
        "// rule Hidden { condition: true }\n"
        '/* include "x" */\n'
        'rule A {\n  strings:\n    $a = "rule B"\n  condition:\n    $a\n}\n'
    )
    BitdefenderConfig.model_validate(_block(yara={"signature": signature}))


def test_unknown_keys_fail() -> None:
    with pytest.raises(ValidationError, match="extra"):
        BitdefenderConfig.model_validate(_block(detection={**PROCESS, "mode": "x"}))
    with pytest.raises(ValidationError, match="extra"):
        BitdefenderConfig.model_validate(_block(yara={**YARA, "imports": ["pe"]}))


def test_a_signature_alias_is_found_and_its_anchor_is_not() -> None:
    text = (
        "configurations:\n"
        "  harfanglab:\n"
        "    yara:\n"
        "      signature: &sig |\n"
        "        rule A { condition: true }\n"
        "  bitdefender:\n"
        "    yara:\n"
        "      signature: *sig\n"
    )
    assert aliased_signatures(text, ["harfanglab", "bitdefender"]) == ["bitdefender"]
    written = text.replace("*sig", "|\n        rule A { condition: true }")
    assert aliased_signatures(written, ["harfanglab", "bitdefender"]) == []


@pytest.mark.parametrize(
    ("code", "block"),
    [
        (
            "bitdefender_criterion_relation",
            _block(
                detection=_detection(
                    "file",
                    {"field": "File.Name", "is": "a.exe"},
                    {"field": "File.CertificateSignedStatus", "any": ["is_signed"]},
                )
            ),
        ),
        (
            "bitdefender_criterion_relation",
            _block(
                detection=_detection(
                    "connection",
                    {"field": "Connection.Domain", "is": "x"},
                    {"field": "Connection.Protocol", "any": ["smb"]},
                )
            ),
        ),
        (
            "bitdefender_criterion_relation",
            _block(
                detection=_detection("registry", {"field": "Registry.DataType", "any": ["dword"]})
            ),
        ),
        (
            "bitdefender_criterion_shape",
            _block(detection=_detection("process", {"field": "Process.Name", "is": True})),
        ),
        (
            "bitdefender_criterion_shape",
            _block(detection=_detection("process", {"field": "Process.Name", "any": ["a", False]})),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "connection",
                    {"field": "Connection.Bucket.Name", "is": "b"},
                    {"field": "Connection.Role.Name", "is": "r"},
                    alert="x",
                )
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection("connection", {"field": "Connection.Bucket.Name", "is": "b"})
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "connection",
                    {"field": "Connection.Domain", "is": "x"},
                    {"field": "Connection.Protocol", "is": "smb"},
                    {"field": "Connection.URL", "is": "u"},
                )
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(detection=_detection("email", {"field": "Email.Sender", "is": "x"})),
        ),
    ],
)
def test_specification_1_1_rules(code: str, block: dict[str, Any]) -> None:
    assert _codes(block) == {code}


@pytest.mark.parametrize(
    ("block", "expected"),
    [
        (_block(), [("bitdefender_rule_kind", ())]),
        (
            _block(detection={**PROCESS, "target": "flow"}),
            [("bitdefender_target", ("detection", "target"))],
        ),
        (
            _block(
                detection=_detection(
                    "process",
                    {"field": "Process.Name", "is": "a"},
                    {"field": "Process.Hash", "is": "b"},
                    {"field": "Process.Name"},
                )
            ),
            [
                ("bitdefender_criterion_field", ("detection", "criteria", "1")),
                ("bitdefender_criterion_shape", ("detection", "criteria", "2")),
            ],
        ),
        (
            _block(detection={"target": "process", "criteria": []}),
            [("bitdefender_criterion_shape", ("detection", "criteria"))],
        ),
        (
            _block(
                detection=_detection("connection", {"field": "Connection.Protocol", "is": "smb"})
            ),
            [("bitdefender_criteria_combination", ("detection", "criteria"))],
        ),
        (
            _block(detection=PROCESS, severity="Critical", targets={"companies": []}),
            [("bitdefender_severity", ("severity",)), ("bitdefender_targets_shape", ("targets",))],
        ),
        (
            _block(
                detection=_detection("registry", {"field": "Registry.Key", "is": "HKLM\\x"}),
                actions={"isolate": True, "quarantine": True},
            ),
            [("bitdefender_action_scope", ("actions", "quarantine"))],
        ),
        (
            _block(yara={"signature": YARA["signature"] + "// \u00e9\n"}),
            [("bitdefender_yara_ascii", ("yara", "signature"))],
        ),
    ],
)
def test_each_code_is_reported_at_its_field_path(
    block: dict[str, Any], expected: list[tuple[str, tuple[str, ...]]]
) -> None:
    assert sorted(_errors(block)) == sorted(expected)


def test_validate_reports_the_code_at_its_path() -> None:
    from opentide.loading.object_loader import load_object_for_validation
    from opentide.validation.errors import issues_from_pydantic

    document = yaml.safe_load(
        (FIXTURES / "invalid" / "rule-bitdefender-criterion-field.yaml").read_text(encoding="utf-8")
    )
    with pytest.raises(ValidationError) as caught:
        load_object_for_validation(document, "rule")
    issues = issues_from_pydantic(caught.value)
    assert [(issue.code, issue.field_path) for issue in issues] == [
        (
            "bitdefender_criterion_field",
            ("configurations", "bitdefender", "detection", "criteria", "0"),
        )
    ]


def test_the_catalogue_lists_the_specification_connection_fields() -> None:
    from opentide.platforms.bitdefender.criteria import catalogue

    connection = catalogue().target_fields("connection")

    resources = [
        "File",
        "Application",
        "KeyVault",
        "Role",
        "Policy",
        "SharingLink",
        "Url",
        "SshKey",
        "LaunchTemplate",
        "ServicePrincipal",
        "UserGroup",
        "AutomationAccount",
        "AutomationAccountHook",
        "Api",
        "CertificateAuthority",
        "Bucket",
        "ConfluencePage",
        "JiraProject",
    ]
    expected = {f"Connection.{r}.Name" for r in resources} | {
        f"Connection.{r}.Operation" for r in [*resources, "Email"]
    }
    expected |= {"Connection.SourceUser", "Connection.DestinationUser", "Connection.Email.Subject"}
    assert expected <= connection
    assert len(connection) == 24 + len(expected)


@pytest.mark.parametrize(
    ("code", "block"),
    [
        ("bitdefender_targets_shape", _block(detection=PROCESS, targets={})),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "connection",
                    {"field": "Connection.URL", "is": "u"},
                    {"field": "Connection.SMBDomain", "is": "d"},
                )
            ),
        ),
        (
            "bitdefender_criteria_combination",
            _block(detection=_detection("file", {"field": "File.MD5", "is": "a" * 32})),
        ),
        (
            "bitdefender_criteria_combination",
            _block(
                detection=_detection(
                    "file",
                    {"field": "File.Name", "is": "a.exe"},
                    {"field": "File.CertificateSigner", "is": "x"},
                    {"field": "File.CertificateSignedStatus", "is": "is_unsigned"},
                )
            ),
        ),
        (
            "bitdefender_criterion_value",
            _block(
                detection=_detection(
                    "email", {"field": "Email.Operation", "is": "teleported"}, alert="x"
                )
            ),
        ),
    ],
)
def test_the_catalogue_pairing_rules_hold(code: str, block: dict[str, Any]) -> None:
    assert _codes(block) == {code}


def test_an_unknown_field_is_an_error_on_a_closed_target_and_a_warning_elsewhere() -> None:
    from opentide.platforms.bitdefender.advisories import bitdefender_advisories

    closed = _block(detection=_detection("process", {"field": "Email.Sender", "is": "x"}))
    assert _errors(closed) == [("bitdefender_criterion_field", ("detection", "criteria", "0"))]
    open_target = _detection("email", {"field": "Email.Nonexistent", "is": "x"}, alert="a")
    BitdefenderConfig.model_validate(_block(detection=open_target))
    rule = {"configurations": {"bitdefender": _block(detection=open_target)}}
    warned = [(a.code, a.field_path) for a in bitdefender_advisories(rule)]
    assert warned == [
        (
            "bitdefender_criterion_field",
            ("configurations", "bitdefender", "detection", "criteria", "0"),
        )
    ]
