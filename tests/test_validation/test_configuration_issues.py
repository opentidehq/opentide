"""`configuration_file_issues`: one configuration file, merged onto its earlier layers.

`tests/fixtures/specifications/sharing` is a verbatim copy of
`fixtures/sharing/{valid,invalid}/*.toml` from opentidehq/specifications at
`SPEC_COMMIT`. Refresh the copy when the upstream fixtures change.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.validation.configuration import (
    configuration_file_issues,
    configuration_text_issues,
    merge_layers,
)

SPEC_COMMIT = "7fd2e92733706d1dc5e0ce82968463d0336117bd"
SHARING = Path(__file__).resolve().parents[1] / "fixtures" / "specifications" / "sharing"

#: `EXPECTED_INVALID` of `scripts/sharing_fixtures.py` at `SPEC_COMMIT`.
EXPECTED_INVALID = {
    "unknown-distribution.toml": "unknown_key",
    "legacy-targets-table.toml": "unknown_key",
    "duplicate-name.toml": "duplicate_name",
    "missing-url.toml": "missing_field",
    "bad-name.toml": "name_invalid",
    "bad-max-tlp.toml": "max_tlp_unknown",
    "missing-max-tlp.toml": "missing_field",
    "bad-organisation-uuid.toml": "organisation_uuid_invalid",
    "bad-object-type.toml": "object_type_unknown",
}


def _load(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _codes(issues: list[Any]) -> set[str]:
    return {issue.code for issue in issues}


# --- sharing.toml ----------------------------------------------------------------------


def test_every_invalid_sharing_fixture_is_vendored() -> None:
    assert sorted(path.name for path in (SHARING / "invalid").glob("*.toml")) == sorted(
        EXPECTED_INVALID
    )


@pytest.mark.parametrize("name", sorted(EXPECTED_INVALID))
def test_invalid_sharing_fixture_returns_exactly_its_code(name: str) -> None:
    issues = configuration_file_issues("sharing.toml", _load(SHARING / "invalid" / name))
    errors = [issue for issue in issues if issue.severity == "error"]
    assert _codes(errors) == {EXPECTED_INVALID[name]}
    assert all(issue.field_path or issue.code == "unknown_key" for issue in errors)


def test_valid_sharing_fixture_has_no_issue() -> None:
    issues = configuration_file_issues(
        "sharing.toml",
        _load(SHARING / "valid" / "sharing.toml"),
        status_names={"PRODUCTION", "STAGING"},
    )
    assert issues == []


def test_override_applied_to_sharing_equals_merged() -> None:
    from opentide.sharing.config import merge_sharing_documents
    from opentide.sharing.constants import TLP_ORDER

    base = _load(SHARING / "valid" / "sharing.toml")
    override = _load(SHARING / "valid" / "override.toml")
    expected = _load(SHARING / "valid" / "merged.toml")
    merged = merge_sharing_documents(
        [base, override], status_names=frozenset({"PRODUCTION", "STAGING"}), tlp_names=TLP_ORDER
    )
    assert merged.ok
    assert [block.name for block in merged.blocks] == [block["name"] for block in expected["misp"]]
    for block, raw in zip(merged.blocks, expected["misp"], strict=True):
        assert block.url == raw["url"]
        assert block.max_tlp == raw["max_tlp"]
        assert block.enabled is raw.get("enabled", False)
        assert list(block.rule_statuses) == raw.get("rule_statuses", ["PRODUCTION"])
        assert block.organisation_uuid == raw.get("organisation_uuid")


def test_override_is_checked_on_top_of_its_base_layer() -> None:
    issues = configuration_file_issues(
        "sharing.toml",
        _load(SHARING / "valid" / "override.toml"),
        earlier_layers=[_load(SHARING / "valid" / "sharing.toml")],
        status_names={"PRODUCTION", "STAGING"},
    )
    assert issues == []


def test_override_alone_is_not_missing_field_when_partial() -> None:
    issues = configuration_file_issues(
        "sharing.toml", _load(SHARING / "valid" / "override.toml"), partial=True
    )
    assert "missing_field" not in _codes(issues)


def test_new_name_in_a_later_layer_must_carry_required_keys() -> None:
    issues = configuration_file_issues(
        "sharing.toml", {"misp": [{"name": "misp-new", "max_tlp": "amber"}]}
    )
    assert {issue.field_path[-1] for issue in issues if issue.code == "missing_field"} == {
        "url",
        "api_key",
    }


def test_disabled_block_still_needs_required_keys() -> None:
    issues = configuration_file_issues(
        "sharing.toml", {"misp": [{"name": "off", "enabled": False, "url": "https://x.example"}]}
    )
    assert _codes(issues) == {"missing_field"}


def test_reserved_sharing_codes() -> None:
    document = {
        "misp": [
            {
                "name": "misp-internal",
                "url": "https://misp.internal.example.org",
                "api_key": "literal-secret-key",
                "max_tlp": "amber",
                "rule_statuses": ["NOPE"],
            }
        ],
        "opencti": [{"name": "sector"}],
    }
    issues = configuration_file_issues("sharing.toml", document, sharing_directory=True)
    by_code = {issue.code: issue for issue in issues}
    assert by_code["rule_status_unknown"].severity == "error"
    assert by_code["sharing_directory"].severity == "error"
    assert by_code["api_key_literal"].severity == "warning"
    assert by_code["unknown_connector"].severity == "warning"
    literal = by_code["api_key_literal"]
    assert "misp-internal" in literal.message and "api_key" in literal.message
    assert all("literal-secret-key" not in issue.message for issue in issues)
    assert all("literal-secret-key" not in str(issue.context) for issue in issues)


@pytest.mark.parametrize(
    ("api_key", "literal"),
    [
        ("${MISP_KEY}", False),
        ("${M}", False),
        ("${MISP_KEY_2}", False),
        ("$MISP_KEY", True),
        ("${misp_key}", True),
        ("${_MISP}", True),
        ("${2MISP}", True),
        ("abc123", True),
    ],
)
def test_api_key_reference_form(api_key: str, literal: bool) -> None:
    document = {
        "misp": [{"name": "m", "url": "https://m.example", "api_key": api_key, "max_tlp": "red"}]
    }
    issues = configuration_file_issues("sharing.toml", document)
    assert ("api_key_literal" in _codes(issues)) is literal
    assert not [issue for issue in issues if issue.severity == "error"]


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("00000000-0000-4000-8aaa-000000000002", True),
        ("ABCDEF01-2345-6789-ABCD-EF0123456789", True),
        ("abcdef0123456789abcdef0123456789", False),
        ("internal-org", False),
    ],
)
def test_organisation_uuid_is_hex_either_case(value: str, ok: bool) -> None:
    document = {
        "misp": [
            {
                "name": "m",
                "url": "https://m.example",
                "api_key": "${KEY}",
                "max_tlp": "red",
                "organisation_uuid": value,
            }
        ]
    }
    codes = _codes(configuration_file_issues("sharing.toml", document))
    assert ("organisation_uuid_invalid" in codes) is not ok


def test_top_level_scalar_is_unknown_key() -> None:
    assert _codes(configuration_file_issues("sharing.toml", {"enabled": True})) == {"unknown_key"}


def test_same_name_on_two_connectors_in_one_layer_is_duplicate() -> None:
    document = {
        "misp": [{"name": "shared", "url": "https://a.example", "api_key": "${K}"}],
        "opencti": [{"name": "shared"}],
    }
    assert "duplicate_name" in _codes(configuration_file_issues("sharing.toml", document))


# --- Other configuration files ---------------------------------------------------------


def test_bundled_files_have_no_issue() -> None:
    from opentide.core.root import get_data_root

    root = get_data_root() / "configurations"
    for path in sorted(root.rglob("*.toml")):
        if path.name in {"resources.toml", "__init__.py"}:
            continue
        rel = path.relative_to(root).as_posix()
        assert configuration_file_issues(rel, _load(path)) == [], rel


def test_client_override_is_merged_onto_the_bundled_file() -> None:
    # A two-line override of deployment.toml: statuses come from the bundled file.
    assert configuration_file_issues("deployment.toml", {"promotion": {"enabled": False}}) == []


def test_deployment_unknown_key_and_strategy() -> None:
    issues = configuration_file_issues(
        "deployment.toml",
        {"statuses": [{"name": "X", "description": "x", "strategy": "LATER"}], "colour": 1},
    )
    paths = {issue.field_path: issue.code for issue in issues}
    assert paths[("colour",)] == "unknown_key"
    assert paths[("statuses", "0", "strategy")] == "schema_validation"


def test_promotion_target_must_name_a_merged_status() -> None:
    issues = configuration_file_issues(
        "deployment.toml", {"promotion": {"promotion_target": "LIVE"}}
    )
    assert [(issue.code, issue.field_path) for issue in issues] == [
        ("promotion_target_unknown", ("promotion", "promotion_target"))
    ]


def test_proxy_placeholder_is_a_valid_string() -> None:
    document = {
        "tenants": [
            {
                "name": "Primary",
                "setup": {
                    "url": "$SPLUNK_URL",
                    "port": "$SPLUNK_PORT",
                    "app": "search",
                    "token": "$SPLUNK_TOKEN",
                    "schedule_offset": "$OFFSET",
                    "ssl": "$SPLUNK_SSL",
                },
            }
        ]
    }
    assert configuration_file_issues("platforms/splunk.toml", document) == []


def test_platform_identifier_matches_the_file_stem(tmp_path: Path) -> None:
    path = tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    issues = configuration_file_issues(path, {"platform": {"identifier": "splunk"}})
    assert [(issue.code, issue.field_path) for issue in issues] == [
        ("identifier_mismatch", ("platform", "identifier"))
    ]


def test_tenant_missing_setup_key_names_the_key() -> None:
    issues = configuration_file_issues(
        "platforms/sentinel.toml",
        {"tenants": [{"name": "Primary", "setup": {"workspace_id": "$WS"}}]},
    )
    missing = {issue.field_path[-1] for issue in issues if issue.code == "missing_field"}
    assert "azure_client_secret" in missing
    assert all(issue.field_path[:3] == ("tenants", "0", "setup") for issue in issues)


def test_tenant_strategies_take_preview_or_release() -> None:
    issues = configuration_file_issues(
        "platforms/crowdstrike.toml",
        {
            "tenants": [
                {
                    "name": "T",
                    "strategies": ["PREVIEW", "DELETION"],
                    "setup": {
                        "api": "a",
                        "client_id": "b",
                        "client_secret": "$C",
                        "customer_id": "d",
                    },
                }
            ]
        },
    )
    assert [(issue.code, issue.field_path) for issue in issues] == [
        ("schema_validation", ("tenants", "0", "strategies", "1"))
    ]


def test_secret_value_is_never_repeated() -> None:
    secret = "s3cr3t-value-123"
    issues = configuration_file_issues(
        "platforms/defender_for_endpoint.toml",
        {"tenants": [{"name": "T", "setup": {"client_secret": secret, "port": secret}}]},
    )
    assert issues
    assert all(secret not in issue.message for issue in issues)


def test_unknown_platform_file_uses_the_generic_model() -> None:
    assert configuration_file_issues("platforms/acme.toml", {"platform": {"enabled": True}}) == []


def test_visibility_asset_must_be_declared() -> None:
    issues = configuration_file_issues(
        "visibility.toml",
        {
            "assets": [{"name": "dc", "description": "d", "criticality": "high"}],
            "logsources": [{"name": "l", "description": "d", "system": "splunk", "assets": ["x"]}],
        },
    )
    assert [(issue.code, issue.field_path) for issue in issues] == [
        ("asset_unknown", ("logsources", "0", "assets", "0"))
    ]


def test_schema_vocabulary_table_stays_open() -> None:
    assert configuration_file_issues("schema.toml", {"vocabulary": {"anything": [1]}}) == []
    issues = configuration_file_issues("schema.toml", {"other": {}})
    assert _codes(issues) == {"unknown_key"}


def test_documentation_flavor_is_an_enum() -> None:
    assert configuration_file_issues("documentation.toml", {"flavor": "github"}) == []
    issues = configuration_file_issues("documentation.toml", {"flavor": {"default": "word"}})
    assert issues and all(issue.field_path[0] == "flavor" for issue in issues)


def test_paths_and_legacy_global() -> None:
    assert configuration_file_issues("paths.toml", {"paths": {"objects": {"rule": "r/"}}}) == []
    issues = configuration_file_issues("global.toml", {"paths": {"tide": {"nope": "x"}}})
    assert [issue.field_path for issue in issues] == [("paths", "tide", "nope")]


def test_unrouted_file_is_reported() -> None:
    issues = configuration_file_issues("resources.toml", {})
    assert _codes(issues) == {"not_a_configuration_file"}


def test_text_entry_point_reports_parse_errors() -> None:
    issues = configuration_text_issues("deployment.toml", "[promotion\n")
    assert _codes(issues) == {"config_parse"}
    assert configuration_text_issues("deployment.toml", "[promotion]\nenabled = false\n") == []


def test_merge_layers_replaces_arrays_and_merges_tables() -> None:
    merged = merge_layers([{"a": {"x": 1, "y": [1, 2]}}, {"a": {"y": [3]}, "b": 2}])
    assert merged == {"a": {"x": 1, "y": [3]}, "b": 2}
