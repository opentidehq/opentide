"""Dual-format Splunk/CBC system configuration loading."""

from __future__ import annotations

import pytest

from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES
from opentide.platforms.config import _build_cbc_config, _build_splunk_config


def test_build_splunk_config_legacy_format() -> None:
    config = _build_splunk_config(
        {
            "tide": {"enabled": False, "identifier": "splunk"},
            "setup": {"url": "$SPLUNK_URL", "port": "8089", "app": "search", "ssl": False},
            "secrets": {"token": "$SPLUNK_TOKEN"},
            "defaults": {"cron_schedule": "0 * * * *"},
            "modifiers": {},
        }
    )
    assert config.setup["url"] == "$SPLUNK_URL"
    assert config.secrets["token"] == "$SPLUNK_TOKEN"
    assert config.tenants is None


def test_build_splunk_config_v4_format() -> None:
    config = _build_splunk_config(
        {
            "platform": {
                "enabled": True,
                "identifier": "splunk",
                "name": "Splunk",
                "subschema": "Splunk Sub Schema",
                "description": "desc",
                "flags": [],
            },
            "tenants": [
                {
                    "name": "Primary",
                    "description": "Primary tenant",
                    "setup": {
                        "ssl": True,
                        "url": "https://splunk.example",
                        "port": "8089",
                        "app": "search",
                        "token": "secret",
                        "enterprise_security": True,
                    },
                }
            ],
            "tide": {"enabled": True},
            "setup": {},
            "secrets": {},
            "defaults": {},
        }
    )
    assert config.tenants is not None
    assert config.tenants[0].name == "Primary"
    assert config.tenants[0].setup.enterprise_security is True
    # A tenant without ``strategies`` or ``manual`` takes every run strategy.
    assert config.tenants[0].strategies == DEPLOYABLE_STRATEGIES
    assert config.tenants[0].manual is False


def test_build_splunk_config_array_of_modifier_tables() -> None:
    """Documented ``[[modifiers]]`` is a list. It must not be passed to ``dict()``."""
    config = _build_splunk_config(
        {
            "platform": {
                "enabled": True,
                "identifier": "splunk",
                "name": "Splunk",
                "subschema": "Splunk Sub Schema",
                "description": "desc",
                "flags": [],
            },
            "tenants": [
                {
                    "name": "Primary",
                    "description": "Primary tenant",
                    "setup": {
                        "ssl": True,
                        "url": "https://splunk.example",
                        "port": "8089",
                        "app": "search",
                        "token": "secret",
                    },
                }
            ],
            "modifiers": [
                {
                    "name": "development-inert",
                    "description": "DEVELOPMENT stays inert",
                    "conditions": {"status": ["DEVELOPMENT"]},
                    "modifications": {"disabled": "1"},
                },
                {
                    "name": "improving-lower",
                    "description": "IMPROVING at reduced severity",
                    "conditions": {"status": ["IMPROVING"]},
                    "modifications": {"severity": "low"},
                },
            ],
        }
    )
    assert config.modifiers is not None
    assert len(config.modifiers) == 2
    assert config.modifiers[0].name == "development-inert"
    assert config.modifiers[0].conditions.status == ["DEVELOPMENT"]
    assert config.modifiers[1].name == "improving-lower"
    assert config.modifiers[1].modifications == {"severity": "low"}


def test_build_cbc_config_v4_format() -> None:
    config = _build_cbc_config(
        {
            "platform": {
                "enabled": True,
                "identifier": "carbon_black_cloud",
                "name": "CBC",
                "subschema": "CBC EDR Sub Schema",
                "description": "desc",
                "flags": [],
            },
            "tenants": [
                {
                    "name": "org-a",
                    "description": "Org A",
                    "setup": {
                        "ssl": True,
                        "url": "https://cbc.example",
                        "org_key": "key",
                        "token": "token",
                    },
                }
            ],
            "tide": {"enabled": True},
            "setup": {},
            "secrets": {},
            "validation": {},
        }
    )
    assert config.tenants is not None
    assert config.tenants[0].setup.org_key == "key"
    assert config.tenants[0].strategies == DEPLOYABLE_STRATEGIES
    assert config.tenants[0].manual is False


def test_build_system_config_uses_tenant_identity_not_rule_schema() -> None:
    from opentide.platforms.config import build_system_config

    config = build_system_config(
        "crowdstrike",
        {
            "platform": {
                "enabled": True,
                "identifier": "crowdstrike",
                "name": "Crowdstrike Falcon Correlation Rules",
                "subschema": "Crowdstrike",
                "description": "desc",
                "flags": [""],
            }
        },
    )
    assert config.platform.identifier == "crowdstrike"
    assert config.platform.enabled is True
    assert config.platform.name == "Crowdstrike Falcon Correlation Rules"


def _splunk_tenants(*setups: dict) -> list:
    tenants = [
        {
            "name": f"Tenant {index}",
            "setup": {"url": "https://splunk.example", "port": "8089", "app": "search", **setup},
        }
        for index, setup in enumerate(setups)
    ]
    config = _build_splunk_config({"platform": {"enabled": True}, "tenants": tenants})
    assert config.tenants is not None
    return list(config.tenants)


def test_splunk_tenant_ssl_defaults_to_verifying() -> None:
    (tenant,) = _splunk_tenants({})
    assert tenant.setup.ssl is True


def test_each_splunk_tenant_keeps_its_own_ssl() -> None:
    strict, lenient = _splunk_tenants({"ssl": True}, {"ssl": False})
    assert strict.setup.ssl is True
    assert lenient.setup.ssl is False


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("false", False),
        ("False", False),
        ("0", False),
        ("no", False),
        (" off ", False),
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
    ],
)
def test_splunk_tenant_ssl_from_an_environment_variable_is_a_boolean(
    monkeypatch: pytest.MonkeyPatch, text: str, expected: bool
) -> None:
    """``ssl = "$SPLUNK_SSL"`` resolves to text; the string "false" must not verify."""
    monkeypatch.setenv("SPLUNK_SSL", text)
    (tenant,) = _splunk_tenants({"ssl": "$SPLUNK_SSL"})
    assert tenant.setup.ssl is expected


def test_splunk_tenant_ssl_placeholder_left_unset_is_kept_for_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SPLUNK_SSL_UNSET", raising=False)
    (tenant,) = _splunk_tenants({"ssl": "$SPLUNK_SSL_UNSET"})
    assert tenant.setup.ssl == "$SPLUNK_SSL_UNSET"


@pytest.mark.parametrize("value", ["maybe", "", 0, 1, 2.0, ["false"]])
def test_splunk_tenant_ssl_refuses_anything_but_a_boolean(value: object) -> None:
    with pytest.raises(
        ValueError, match=r"splunk tenant 'Tenant 0' setup: ssl must be true or false"
    ):
        _splunk_tenants({"ssl": value})


def test_cbc_tenant_ssl_from_an_environment_variable_is_a_boolean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CBC_SSL", "false")
    config = _build_cbc_config(
        {
            "platform": {"enabled": True},
            "tenants": [
                {
                    "name": "Primary",
                    "setup": {"ssl": "$CBC_SSL", "url": "u", "org_key": "o", "token": "t"},
                }
            ],
        }
    )
    assert config.tenants[0].setup.ssl is False


def test_generic_tenant_ssl_refuses_anything_but_a_boolean() -> None:
    from opentide.platforms.config import _load_tenants

    with pytest.raises(ValueError, match=r"harfanglab tenant 'Primary' setup: ssl must be"):
        _load_tenants("harfanglab", [{"name": "Primary", "setup": {"ssl": "sometimes"}}])
