"""Dual-format Splunk/CBC system configuration loading."""

from __future__ import annotations

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
                    "deployment": "ALWAYS",
                    "setup": {
                        "proxy": False,
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
                    "deployment": "ALWAYS",
                    "setup": {
                        "proxy": False,
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
