"""sharing.toml merge and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.core.files import _fetch_configs
from opentide.sharing.config import MispBlock, SharingConfig, load_sharing, merge_sharing_documents
from opentide.sharing.constants import REDACTION_MARKER, TLP_ORDER
from opentide.validation.checks.kinds import ValidateCheck
from opentide.validation.session import run_validation

_STATUSES = frozenset({"DESIGN", "STAGING", "PRODUCTION"})


def _block(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "name": "misp-internal",
        "url": "https://misp.internal.example.org",
        "api_key": "${MISP_KEY}",
        "max_tlp": "amber",
    }
    base.update(overrides)
    return base


def _merge(*layers: dict[str, object]) -> SharingConfig:
    return merge_sharing_documents(layers, status_names=_STATUSES, tlp_names=TLP_ORDER)


def test_two_line_override_keeps_earlier_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "secret-value")
    merged = _merge(
        {"misp": [_block()]},
        {"misp": [{"name": "misp-internal", "enabled": True}]},
    )
    assert merged.ok
    assert len(merged.blocks) == 1
    block = merged.blocks[0]
    assert block.enabled is True
    assert block.url == "https://misp.internal.example.org"
    assert block.max_tlp == "amber"
    assert block.api_key_env == "MISP_KEY"
    assert block.resolved_api_key() == "secret-value"
    assert "secret-value" not in repr(block)


def test_new_name_appends_and_lists_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "one")
    monkeypatch.setenv("MISP_OTHER", "two")
    merged = _merge(
        {"misp": [_block(object_types=["rule", "threat"])]},
        {
            "misp": [
                {"name": "misp-internal", "object_types": ["rule"]},
                _block(name="misp-isac", api_key="${MISP_OTHER}", max_tlp="green"),
            ]
        },
    )
    assert [block.name for block in merged.blocks] == ["misp-internal", "misp-isac"]
    assert merged.blocks[0].object_types == ("rule",)
    assert merged.blocks[1].max_tlp == "green"


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "one")
    block = _merge({"misp": [_block()]}).blocks[0]
    assert block.enabled is False
    assert block.object_types == ("threat", "objective", "rule")
    assert block.rule_statuses == ("PRODUCTION",)
    assert block.publish is False
    assert block.verify_ssl is True
    assert block.organisation_uuid is None


@pytest.mark.parametrize(
    ("document", "code"),
    [
        ({"sharing": {"enabled": True}}, "unknown_key"),
        ({"targets": {"misp": {"url": "https://example.org"}}}, "unknown_key"),
        ({"misp": [_block(), _block()]}, "duplicate_name"),
        ({"misp": [_block(name="Bad Name")]}, "name_invalid"),
        ({"misp": [_block(name="")]}, "missing_field"),
        ({"misp": [{"name": "misp-internal"}]}, "missing_field"),
        ({"misp": [_block(max_tlp="purple")]}, "max_tlp_unknown"),
        ({"misp": [_block(organisation_uuid="not-a-uuid")]}, "organisation_uuid_invalid"),
        ({"misp": [_block(object_types=["feed"])]}, "object_type_unknown"),
        ({"misp": [_block(rule_statuses=["NOPE"])]}, "rule_status_unknown"),
        ({"misp": [_block(distribution="1")]}, "unknown_key"),
        ({"misp": [_block(url="ftp://files.example")]}, "url_invalid"),
    ],
)
def test_checker_codes(document: dict[str, object], code: str) -> None:
    merged = _merge(document)
    assert code in {issue.code for issue in merged.errors}
    assert merged.blocks == ()


def test_duplicate_name_across_integrations() -> None:
    merged = _merge(
        {
            "misp": [_block(name="shared")],
            "opencti": [{"name": "shared", "url": "https://opencti.example"}],
        }
    )
    assert any(issue.code == "duplicate_name" for issue in merged.errors)
    assert any(issue.code == "unknown_integration" for issue in merged.warnings)


def test_unknown_integration_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "one")
    merged = _merge(
        {"misp": [_block()], "opencti": [{"name": "sector", "url": "https://x.example"}]}
    )
    assert merged.ok
    assert [block.name for block in merged.blocks] == ["misp-internal"]
    assert merged.warnings[0].integration == "opencti"


def test_literal_api_key_warns_without_printing_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISP_KEY", raising=False)
    secret = "literal-secret-value"
    merged = _merge({"misp": [_block(api_key=secret)]})
    assert merged.ok
    warning = merged.warnings[0]
    assert warning.code == "api_key_literal"
    assert secret not in warning.message
    assert REDACTION_MARKER in warning.message
    assert merged.blocks[0].api_key_literal is True
    assert merged.blocks[0].resolved_api_key() == secret
    rendered = repr(merged.blocks[0])
    assert secret not in rendered


def test_optional_organisation_uuid_and_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "one")
    block = _merge(
        {
            "misp": [
                _block(
                    organisation_uuid="00000000-0000-4000-8aaa-000000000002",
                    publish=True,
                    verify_ssl=False,
                    enabled=True,
                    rule_statuses=["STAGING", "PRODUCTION"],
                )
            ]
        }
    ).blocks[0]
    assert block.organisation_uuid == "00000000-0000-4000-8aaa-000000000002"
    assert block.publish is True
    assert block.verify_ssl is False
    assert block.rule_statuses == ("STAGING", "PRODUCTION")


def test_invalid_bool_and_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "one")
    merged = _merge({"misp": [_block(enabled="yes", object_types="rule")]})
    assert {issue.code for issue in merged.errors} >= {"invalid_value"}
    assert merged.blocks == ()


def test_empty_env_counts_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "")
    block = _merge({"misp": [_block()]}).blocks[0]
    assert block.api_key_unset is True
    assert block.resolved_api_key() is None


def test_unreadable_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    config_dir = tmp_path / ".opentide" / "configurations"
    config_dir.mkdir(parents=True)
    (config_dir / "sharing.toml").write_text("[[misp]\n", encoding="utf-8")
    loaded = load_sharing(tmp_path)
    assert any(issue.code == "config_parse" for issue in loaded.errors)
    assert "secret" not in loaded.errors[0].message


def test_unset_env_keeps_disabled_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISP_KEY", raising=False)
    block = _merge({"misp": [_block()]}).blocks[0]
    assert block.api_key_unset is True
    assert block.resolved_api_key() is None
    assert block.api_key_env == "MISP_KEY"


def test_trailing_slash_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_KEY", "one")
    block = _merge({"misp": [_block(url="https://misp.internal.example.org/")]}).blocks[0]
    assert block.url == "https://misp.internal.example.org"


def test_load_layers_from_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    monkeypatch.setenv("MISP_INTERNAL_API_KEY", "workspace-secret")
    config_dir = tmp_path / ".opentide" / "configurations"
    config_dir.mkdir(parents=True)
    (config_dir / "sharing.toml").write_text(
        "\n".join(
            [
                "[[misp]]",
                'name = "misp-internal"',
                "enabled = true",
                'url = "https://misp.internal.example.org"',
                'api_key = "${MISP_INTERNAL_API_KEY}"',
                'max_tlp = "amber"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    loaded = load_sharing(tmp_path)
    assert loaded.ok
    assert loaded.blocks[0].enabled is True
    assert loaded.blocks[0].resolved_api_key() == "workspace-secret"
    assert "workspace-secret" not in repr(loaded)


def test_sharing_directory_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    sharing = tmp_path / ".opentide" / "configurations" / "sharing"
    sharing.mkdir(parents=True)
    (sharing / "misp.toml").write_text("name = 'nope'\n", encoding="utf-8")
    loaded = load_sharing(tmp_path)
    assert any(issue.code == "sharing_directory" for issue in loaded.errors)


def test_parent_layer_merges_by_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    monkeypatch.setenv("MISP_KEY", "parent-secret")
    parent = tmp_path / ".opentide" / "configurations"
    parent.mkdir(parents=True)
    (parent / "sharing.toml").write_text(
        "\n".join(
            [
                "[[misp]]",
                'name = "misp-internal"',
                'url = "https://misp.internal.example.org"',
                'api_key = "${MISP_KEY}"',
                'max_tlp = "red"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    child = tmp_path / "child"
    child_config = child / ".opentide" / "configurations"
    child_config.mkdir(parents=True)
    (child_config / "sharing.toml").write_text(
        '[[misp]]\nname = "misp-internal"\nenabled = true\n',
        encoding="utf-8",
    )
    loaded = load_sharing(child)
    assert loaded.ok
    assert loaded.blocks[0].enabled is True
    assert loaded.blocks[0].max_tlp == "red"
    assert loaded.blocks[0].resolved_api_key() == "parent-secret"


def test_fetch_configs_leaves_sharing_toml_to_the_sharing_loader(tmp_path: Path) -> None:
    (tmp_path / "sharing.toml").write_text('[[misp]]\nname = "a"\n', encoding="utf-8")
    (tmp_path / "global.toml").write_text("[tide]\nidentifier = 'demo'\n", encoding="utf-8")
    configs = _fetch_configs(tmp_path)
    assert "sharing" not in configs
    assert configs["global"]["tide"]["identifier"] == "demo"


def test_validate_sharing_config_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    config_dir = tmp_path / ".opentide" / "configurations"
    config_dir.mkdir(parents=True)
    (config_dir / "sharing.toml").write_text("[sharing]\nenabled = true\n", encoding="utf-8")
    report = run_validation(checks=frozenset({ValidateCheck.sharing_config}))
    assert any(issue.code == "unknown_key" for issue in report.issues)
    assert report.ok is False


def test_block_repr_hides_secret() -> None:
    block = MispBlock(
        name="misp-internal",
        url="https://misp.example",
        max_tlp="amber",
        api_key="super-secret",
        api_key_env=None,
        api_key_literal=True,
        api_key_unset=False,
    )
    assert "super-secret" not in repr(block)
