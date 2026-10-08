"""Tests for Elastic platform registration and tenant setup (RFC 0007 §1 / #387)."""

from __future__ import annotations

import pytest

from opentide.platforms.config import build_system_config
from opentide.platforms.enabled import enabled_systems


def test_elastic_platform_loads_and_is_off_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # Bundled default has enabled = false
    raw = {
        "platform": {
            "enabled": False,
            "identifier": "elastic",
            "name": "Elastic Security",
        },
        "tenants": [],
    }
    cfg = build_system_config("elastic", raw)
    assert cfg.platform.enabled is False
    with monkeypatch.context() as m:
        m.setattr("opentide.platforms.enabled.resolve_configurations", lambda: {"systems": {"elastic": {"platform": {"enabled": False}}}})
        assert "elastic" not in enabled_systems()


def test_tenant_missing_elasticsearch_url_fails() -> None:
    raw = {
        "platform": {"enabled": True, "identifier": "elastic"},
        "tenants": [
            {
                "name": "staging",
                "setup": {
                    "url": "https://kibana.test",
                    "api_key": "$ELASTIC_API_KEY",
                },
            }
        ],
    }
    with pytest.raises(ValueError, match="missing required key.*elasticsearch_url"):
        build_system_config("elastic", raw)


def test_tenant_literal_api_key_rejected() -> None:
    raw = {
        "platform": {"enabled": True, "identifier": "elastic"},
        "tenants": [
            {
                "name": "staging",
                "setup": {
                    "url": "https://kibana.test",
                    "elasticsearch_url": "https://es.test",
                    "api_key": "literal-secret-key",  # Not $ENV reference
                },
            }
        ],
    }
    with pytest.raises(ValueError, match="api_key must be an environment variable reference"):
        build_system_config("elastic", raw)


def test_tenant_with_retired_proxy_key_rejected() -> None:
    raw = {
        "platform": {"enabled": True, "identifier": "elastic"},
        "tenants": [
            {
                "name": "staging",
                "setup": {
                    "url": "https://kibana.test",
                    "elasticsearch_url": "https://es.test",
                    "api_key": "$ELASTIC_API_KEY",
                    "proxy": True,
                },
            }
        ],
    }
    with pytest.raises(ValueError, match="proxy key is retired"):
        build_system_config("elastic", raw)


def test_tenant_valid_env_api_key_loads() -> None:
    raw = {
        "platform": {"enabled": True, "identifier": "elastic"},
        "tenants": [
            {
                "name": "staging",
                "setup": {
                    "url": "https://kibana.test",
                    "elasticsearch_url": "https://es.test",
                    "api_key": "$ELASTIC_API_KEY",
                    "space": "staging",
                    "suppression": True,
                },
            }
        ],
    }
    cfg = build_system_config("elastic", raw)
    assert cfg.tenants is not None
    assert len(cfg.tenants) == 1
    tenant = cfg.tenants[0]
    assert tenant.setup.url == "https://kibana.test"
    assert tenant.setup.elasticsearch_url == "https://es.test"
    assert tenant.setup.space == "staging"
    assert tenant.setup.suppression is True
