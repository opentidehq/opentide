"""Unit tests for Elastic Security live validator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.validator import ElasticSecurityValidator


def _tenant() -> ConfigurationModels.Systems.ElasticSecurity.Tenant:
    return ConfigurationModels.Systems.ElasticSecurity.Tenant(
        name="primary",
        description="Primary tenant",
        deployment="ALWAYS",
        setup=ConfigurationModels.Systems.ElasticSecurity.Tenant.Setup(
            proxy=False,
            ssl=False,
            kibana_url="https://kibana.example.com:5601",
            api_key="secret-api-key",
            space="default",
            min_version="8.14.0",
        ),
    )


def _rule():
    return load_rule_from_dict(
        {
            "name": "Live Test Rule",
            "description": "Rule for preview test",
            "metadata": {
                "uuid": "00000000-0000-4000-8003-000000000088",
                "schema": "rule::1.0",
                "version": 1,
                "created": "2026-01-01",
                "modified": "2026-01-02",
                "tlp": "amber",
                "author": "SecEng",
            },
            "response": {"alert_severity": "High"},
            "status": "PRODUCTION",
            "configurations": {
                "elastic_security": {
                    "schema": "platform::elastic_security::1.0",
                    "type": "query",
                    "query": "process.name: test.exe",
                    "index": ["logs-*"],
                }
            },
        }
    )


def test_validator_preview_success() -> None:
    validator = ElasticSecurityValidator()
    tenant = _tenant()
    rule = _rule()

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "isAborted": False,
        "logs": [],
        "signals_count": 0,
    }

    with patch("opentide.deployment.planning.OpenTide") as mock_opentide:
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = [tenant]
        with patch("requests.Session.post", return_value=mock_resp) as mock_post:
            validator.validate([rule])
            assert mock_post.called
            post_body = mock_post.call_args[1]["json"]
            assert post_body.get("invocationCount") == 1
            assert "timeframeEnd" in post_body


def test_validator_preview_aborted_raises() -> None:
    validator = ElasticSecurityValidator()
    tenant = _tenant()
    rule = _rule()

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "isAborted": True,
        "logs": [],
    }

    with (
        patch("opentide.deployment.planning.OpenTide") as mock_opentide,
        patch("requests.Session.post", return_value=mock_resp),
        pytest.raises(RuntimeError, match="was aborted by Kibana"),
    ):
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = [tenant]
        validator.validate([rule])


def test_validator_preview_logs_errors_raises() -> None:
    validator = ElasticSecurityValidator()
    tenant = _tenant()
    rule = _rule()

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "isAborted": False,
        "logs": [{"errors": ["Unknown field 'foo.bar' in query"]}],
    }

    with (
        patch("opentide.deployment.planning.OpenTide") as mock_opentide,
        patch("requests.Session.post", return_value=mock_resp),
        pytest.raises(RuntimeError, match="reported errors: Unknown field 'foo.bar' in query"),
    ):
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = [tenant]
        validator.validate([rule])
