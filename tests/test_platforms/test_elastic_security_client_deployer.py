"""Unit tests for Elastic Security client and deployer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.client import ElasticSecurityClient
from opentide.platforms.elastic_security.deployer import ElasticSecurityDeploy


def _tenant(
    space: str = "default",
    min_version: str = "8.14.0",
) -> ConfigurationModels.Systems.ElasticSecurity.Tenant:
    return ConfigurationModels.Systems.ElasticSecurity.Tenant(
        name="primary",
        description="Primary tenant",
        deployment="ALWAYS",
        setup=ConfigurationModels.Systems.ElasticSecurity.Tenant.Setup(
            proxy=False,
            ssl=False,
            kibana_url="https://kibana.example.com:5601",
            api_key="secret-api-key",
            space=space,
            overwrite_exceptions=True,
            overwrite_action_connectors=True,
            min_version=min_version,
        ),
    )


def test_client_url_construction() -> None:
    # Default space
    client_default = ElasticSecurityClient(
        "https://kibana.example.com:5601", "key", space="default"
    )
    assert (
        client_default.url_for("/api/detection_engine/rules")
        == "https://kibana.example.com:5601/api/detection_engine/rules"
    )

    # Empty space
    client_empty = ElasticSecurityClient("https://kibana.example.com:5601", "key", space="")
    assert (
        client_empty.url_for("/api/detection_engine/rules")
        == "https://kibana.example.com:5601/api/detection_engine/rules"
    )

    # Named space
    client_space = ElasticSecurityClient("https://kibana.example.com:5601", "key", space="soc")
    assert (
        client_space.url_for("/api/detection_engine/rules")
        == "https://kibana.example.com:5601/s/soc/api/detection_engine/rules"
    )


def test_client_headers() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    headers = client.session.headers
    assert headers["kbn-xsrf"] == "true"
    assert headers["Authorization"] == "ApiKey secret-key"


def test_client_import_rules_multipart() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "success_count": 1}

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        result = client.import_rules(
            '{"rule_id": "test-1"}',
            overwrite=True,
            overwrite_exceptions=True,
            overwrite_action_connectors=False,
        )

    assert result["success"] is True
    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["params"] == {
        "overwrite": "true",
        "overwrite_exceptions": "true",
        "overwrite_action_connectors": "false",
    }
    assert "files" in kwargs
    file_tuple = kwargs["files"]["file"]
    assert file_tuple[0] == "rules.ndjson"
    assert file_tuple[1] == b'{"rule_id": "test-1"}'
    assert file_tuple[2] == "application/x-ndjson"


def test_client_patch_rule() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"rule_id": "rule-1", "enabled": False}

    with patch.object(client.session, "patch", return_value=mock_resp) as mock_patch:
        result = client.patch_rule({"rule_id": "rule-1", "enabled": False})

    assert result["enabled"] is False
    mock_patch.assert_called_once_with(
        "https://kibana.example.com:5601/api/detection_engine/rules",
        json={"rule_id": "rule-1", "enabled": False},
        timeout=30,
    )


def test_client_delete_rule() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"rule_id": "rule-1"}

    with patch.object(client.session, "delete", return_value=mock_resp) as mock_delete:
        result = client.delete_rule(rule_id="rule-1")

    assert result["rule_id"] == "rule-1"
    mock_delete.assert_called_once_with(
        "https://kibana.example.com:5601/api/detection_engine/rules",
        params={"rule_id": "rule-1"},
        timeout=30,
    )


def test_client_export_rules_all_uses_bulk_action() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.content = b'{"name":"rule-1"}\n{"exported_count":1}\n'

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        result = client.export_rules()

    assert result == b'{"name":"rule-1"}\n{"exported_count":1}\n'
    mock_post.assert_called_once_with(
        "https://kibana.example.com:5601/api/detection_engine/rules/_bulk_action",
        json={"action": "export", "query": ""},
        timeout=30,
    )


def test_client_export_rules_by_ids_uses_objects() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.content = b'{"name":"rule-1"}\n'

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        result = client.export_rules(rule_ids=["rule-1", "rule-2"])

    assert result == b'{"name":"rule-1"}\n'
    mock_post.assert_called_once_with(
        "https://kibana.example.com:5601/api/detection_engine/rules/_export",
        params={"exclude_export_details": "true"},
        json={"objects": [{"rule_id": "rule-1"}, {"rule_id": "rule-2"}]},
        timeout=30,
    )


def test_deployer_active_rules() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.RELEASE

    rule = load_rule_from_dict(
        {
            "name": "Test Rule",
            "description": "Test description",
            "metadata": {
                "uuid": "00000000-0000-4000-8003-000000000001",
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
                    "query": "process.name: cmd.exe",
                    "index": ["logs-*"],
                }
            },
        }
    )
    mock_batch.rules = [rule]

    with patch(
        "opentide.platforms.elastic_security.deployer.check_status",
        return_value=StatusStrategy.RELEASE,
    ):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)

    mock_client.import_rules.assert_called_once()


def test_deployer_disablement() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.DISABLEMENT

    mock_rule = MagicMock()
    mock_rule.name = "Disabled Rule"
    mock_rule.status = "DISABLED"
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000002"
    mock_rule.configurations.elastic_security.status = "DISABLED"
    mock_rule.configurations.elastic_security.rule_id = None

    mock_batch.rules = [mock_rule]

    with patch(
        "opentide.platforms.elastic_security.deployer.check_status",
        return_value=StatusStrategy.DISABLEMENT,
    ):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)

    mock_client.patch_rule.assert_called_once_with(
        {"rule_id": "00000000-0000-4000-8003-000000000002", "enabled": False}
    )


def test_deployer_deletion() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.DELETION

    mock_rule = MagicMock()
    mock_rule.name = "Deleted Rule"
    mock_rule.status = "DELETED"
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000003"
    mock_rule.configurations.elastic_security.status = "DELETED"
    mock_rule.configurations.elastic_security.rule_id = None

    mock_batch.rules = [mock_rule]

    with patch(
        "opentide.platforms.elastic_security.deployer.check_status",
        return_value=StatusStrategy.DELETION,
    ):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)

    mock_client.delete_rule.assert_called_once_with("00000000-0000-4000-8003-000000000003")


def test_deployer_delete_404_treated_as_success() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)
    # Simulate 404 response error on delete
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    exc = requests.HTTPError("404 Not Found")
    exc.response = mock_resp
    mock_client.delete_rule.side_effect = exc

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.DELETION

    mock_rule = MagicMock()
    mock_rule.name = "Rule 404"
    mock_rule.status = "DELETED"
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000004"
    mock_rule.configurations.elastic_security.status = "DELETED"
    mock_rule.configurations.elastic_security.rule_id = "00000000-0000-4000-8003-000000000004"
    mock_batch.rules = [mock_rule]

    with patch(
        "opentide.platforms.elastic_security.deployer.check_status",
        return_value=StatusStrategy.DELETION,
    ):
        # Should not raise
        deployer.deploy_mdr(mock_batch, mock_client, tenant)


def test_deployer_disable_500_raises() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)
    mock_client.patch_rule.side_effect = requests.HTTPError("500 Internal Server Error")

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.DISABLEMENT

    mock_rule = MagicMock()
    mock_rule.name = "Rule 500"
    mock_rule.status = "DISABLED"
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000005"
    mock_rule.configurations.elastic_security.status = "DISABLED"
    mock_rule.configurations.elastic_security.rule_id = "00000000-0000-4000-8003-000000000005"
    mock_batch.rules = [mock_rule]

    with (
        patch(
            "opentide.platforms.elastic_security.deployer.check_status",
            return_value=StatusStrategy.DISABLEMENT,
        ),
        pytest.raises(requests.HTTPError, match="500 Internal Server Error"),
    ):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)


def test_deployer_import_partial_failure_raises() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)
    # Simulate HTTP 200 with partial failure in body
    mock_client.import_rules.return_value = {
        "success": False,
        "success_count": 0,
        "errors": [
            {"rule_id": "rule-err-1", "error": {"message": "Invalid query syntax in Kuery"}}
        ],
    }

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.RELEASE

    rule = load_rule_from_dict(
        {
            "name": "Failed Rule",
            "description": "Rule that fails import",
            "metadata": {
                "uuid": "rule-err-1",
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
                    "query": "syntax error | pipe",
                    "index": ["logs-*"],
                }
            },
        }
    )
    mock_batch.rules = [rule]

    with (
        patch(
            "opentide.platforms.elastic_security.deployer.check_status",
            return_value=StatusStrategy.RELEASE,
        ),
        patch(
            "opentide.platforms.elastic_security.deployer.compile_rule",
            return_value={"rule_id": "rule-err-1", "name": "Failed Rule"},
        ),
        pytest.raises(
            RuntimeError,
            match="Elastic Security rule import failed: rule 'rule-err-1': Invalid query syntax in Kuery",
        ),
    ):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)


def test_deployer_deploy_via_real_tide_deployment() -> None:
    """Test calling deploy(...) through real TideDeployment without mocking the planner."""
    rule = load_rule_from_dict(
        {
            "name": "Integration Rule",
            "description": "Integration test rule",
            "metadata": {
                "uuid": "00000000-0000-4000-8003-000000000099",
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

    tenant = _tenant()
    deployer = ElasticSecurityDeploy()

    fake_resp = MagicMock(spec=requests.Response)
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"success": True, "success_count": 1}

    with patch("opentide.deployment.planning.OpenTide") as mock_opentide:
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = [tenant]
        with patch("requests.Session.post", return_value=fake_resp) as mock_post:
            deployer.deploy([rule])
            assert mock_post.called
            # The client should have made a call to _import
            call_url = mock_post.call_args[0][0]
            assert "/api/detection_engine/rules/_import" in call_url
