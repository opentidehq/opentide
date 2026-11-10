"""A YARA code the model and the engine both report is shown once (validation.session)."""

from __future__ import annotations

from pathlib import Path

from opentide.validation.issues import ValidationIssue
from opentide.validation.session import _model_yara_codes, _without_engine_reported_yara

RULE = Path("objects/rules/rule.yaml")
SIGNATURE = ("configurations", "bitdefender", "yara", "signature")


def _issue(code: str, path: tuple[str, ...] = SIGNATURE, message: str = "m") -> ValidationIssue:
    return ValidationIssue(code=code, file_path=RULE, field_path=path, message=message)


def test_a_bitdefender_finding_the_engine_reports_is_shown_once() -> None:
    """Bitdefender reports each code as its own finding, not in a schema_validation message."""
    model = [
        _issue("yara_include"),
        _issue("bitdefender_yara_ascii"),
        _issue("bitdefender_targets_shape", ("configurations", "bitdefender", "targets")),
    ]
    engine = [_issue("yara_include"), _issue("bitdefender_yara_ascii")]
    kept = _without_engine_reported_yara(model, engine)
    assert [issue.code for issue in kept] == ["bitdefender_targets_shape"]


def test_the_model_codes_include_bitdefenders_own_findings() -> None:
    codes = _model_yara_codes([_issue("yara_include"), _issue("bitdefender_yara_size")])
    assert codes == {
        (RULE, ("configurations", "bitdefender"), "yara_include"),
        (RULE, ("configurations", "bitdefender"), "bitdefender_yara_size"),
    }


def test_harfanglabs_coded_message_is_still_read() -> None:
    issue = _issue(
        "schema_validation",
        ("configurations", "harfanglab"),
        "HarfangLabConfig validation failed with code(s): yara_include",
    )
    engine = [_issue("yara_include", ("configurations", "harfanglab", "yara", "signature"))]
    assert _without_engine_reported_yara([issue], engine) == []


def test_without_an_engine_finding_the_model_keeps_its_own() -> None:
    model = [_issue("yara_include")]
    assert _without_engine_reported_yara(model, []) == model
