"""``platform_not_enabled`` warnings and their exemption from ``--strict`` (#413)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.disabled_platforms import platform_not_enabled_warnings
from opentide.validation.issues import ValidationIssue
from opentide.validation.session import run_validation

RULE_UUID = "00000000-0000-4000-8003-000000000413"


def test_one_warning_per_disabled_platform_block() -> None:
    body = {
        "configurations": {
            "sentinel": {"query": "x"},
            "splunk": {"query": "x"},
            "elastic": {"query": "x"},
            "splnk": {"query": "x"},
        }
    }
    warnings = platform_not_enabled_warnings(body, {"sentinel"}, object_uuid=RULE_UUID)
    assert [(w.code, w.field_path) for w in warnings] == [
        ("platform_not_enabled", ("configurations", "splunk")),
        ("platform_not_enabled", ("configurations", "elastic")),
    ]
    assert {w.severity for w in warnings} == {"warning"}
    assert {w.object_uuid for w in warnings} == {RULE_UUID}


def test_warning_names_the_setup_flag_with_dashes() -> None:
    body = {"configurations": {"defender_for_endpoint": {"query": "x"}}}
    (warning,) = platform_not_enabled_warnings(body, set())
    assert warning.context == {"platform": "defender_for_endpoint"}
    assert "'opentide setup platforms --defender-for-endpoint'" in warning.message


@pytest.mark.parametrize("block_enabled", [True, False], ids=["block-enabled", "block-disabled"])
def test_warning_does_not_promise_the_block_deploys_once_enabled(block_enabled: bool) -> None:
    """It said the block would deploy once the platform was enabled, even for ``enabled: false``."""
    body = {"configurations": {"splunk": {"enabled": block_enabled, "query": "x"}}}
    (warning,) = platform_not_enabled_warnings(body, set())
    assert warning.message == (
        "this block will not deploy while splunk is disabled in this workspace; "
        "enable splunk with 'opentide setup platforms --splunk'"
    )


@pytest.mark.parametrize("configurations", [None, [], "splunk"], ids=["none", "list", "str"])
def test_no_warning_without_a_configurations_mapping(configurations: Any) -> None:
    assert platform_not_enabled_warnings({"configurations": configurations}, set()) == []


def _index(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "objects": {"rule": {RULE_UUID: body}, "objective": {}, "threat": {}},
        "metaschemas": {},
        "files": {RULE_UUID: "rule.yaml"},
    }


@pytest.fixture
def isolated_session(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    """Only the platform and deprecated-field findings reach the report."""
    for flag in ("VALIDATION_ERROR_RAISED", "VALIDATION_WARNING_RAISED"):
        monkeypatch.delenv(flag, raising=False)
    graph = MagicMock()
    graph.resolve.return_value = MagicMock(file_path=None)
    with (
        patch("opentide.validation.session.Opentide.initialise"),
        patch("opentide.validation.session.PreflightGraph.build", return_value=graph),
        patch("opentide.loading.object_loader.load_object_for_validation"),
        patch("opentide.validation.session.validate_object_vocab_from_metaschema", return_value=[]),
        patch("opentide.validation.session.check_references_for_object", return_value=[]),
        patch("opentide.validation.external_ids.external_id_issues", return_value=[]),
        patch("opentide.validation.external_ids.deployment_state_issues", return_value=[]),
        patch(
            "opentide.validation.deprecated_fields.validate_deprecated_fields_from_metaschema",
            return_value=[],
        ) as deprecated,
        patch("opentide.platforms.enabled.enabled_systems", return_value=["sentinel"]),
    ):
        yield deprecated


_SPLUNK_RULE = {"name": "Imported", "configurations": {"splunk": {"query": "x"}}}


@pytest.mark.usefixtures("isolated_session")
def test_platform_warning_alone_does_not_raise_the_strict_flag() -> None:
    report = run_validation(
        checks=frozenset({ValidateCheck.schema}), index=_index(_SPLUNK_RULE), workers=0
    )
    assert report.ok
    assert [w.code for w in report.warnings] == ["platform_not_enabled"]
    assert not os.environ.get("VALIDATION_WARNING_RAISED")


def test_other_warnings_still_raise_the_strict_flag(isolated_session: MagicMock) -> None:
    isolated_session.return_value = [
        ValidationIssue(code="deprecated_field", severity="warning", message="old")
    ]
    report = run_validation(
        checks=frozenset({ValidateCheck.schema}), index=_index(_SPLUNK_RULE), workers=0
    )
    assert sorted(w.code for w in report.warnings) == ["deprecated_field", "platform_not_enabled"]
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"


@pytest.mark.usefixtures("isolated_session")
def test_checks_without_schema_do_not_read_enabled_platforms() -> None:
    with patch("opentide.platforms.enabled.enabled_systems") as enabled:
        report = run_validation(
            checks=frozenset({ValidateCheck.uuid_format}), index=_index(_SPLUNK_RULE), workers=0
        )
    enabled.assert_not_called()
    assert report.warnings == []


def test_a_misspelled_enabled_key_is_named_in_the_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """``enabeld = true`` left sentinel disabled, and the warning sent the author to
    ``opentide setup platforms`` (post-merge end-to-end run, B08)."""
    monkeypatch.setattr(
        "opentide.validation.disabled_platforms.misspelled_enabled_key",
        lambda platform: ("platform", "enabeld"),
    )
    monkeypatch.setattr(
        "opentide.validation.disabled_platforms.platform_config_path",
        lambda platform: f".opentide/configurations/platforms/{platform}.toml",
    )
    (warning,) = platform_not_enabled_warnings({"configurations": {"sentinel": {}}}, set())
    assert warning.message == (
        "this block will not deploy: .opentide/configurations/platforms/sentinel.toml sets "
        "'enabeld' in [platform], not 'enabled', so sentinel is disabled; "
        "rename the key to 'enabled'"
    )
    assert warning.context == {"platform": "sentinel", "key": "enabeld"}
    assert "setup platforms" not in warning.message


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"platform": {"enabeld": True}}, ("platform", "enabeld")),
        # The older [tide] table, after a [platform] value that is not a table.
        ({"platform": "x", "tide": {"Enabled": True}}, ("tide", "Enabled")),
        ({"platform": {"enabled": True, "name": "x"}}, None),
        ({}, None),
    ],
)
def test_misspelled_enabled_key(
    monkeypatch: pytest.MonkeyPatch, config: dict[str, Any], expected: tuple[str, str] | None
) -> None:
    from opentide.platforms.enabled import misspelled_enabled_key

    monkeypatch.setattr(
        "opentide.platforms.enabled.resolve_configurations",
        lambda: {"systems": {"sentinel": config}},
    )
    assert misspelled_enabled_key("sentinel") == expected
