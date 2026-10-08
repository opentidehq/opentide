"""Tests for ElasticClient and ElasticDeploy (RFC 0007 §4 & §5)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import requests

from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.deployer import ElasticDeploy


def _mock_response(status_code: int = 200, json_data: dict | list | None = None, text: str = ""):
    resp = requests.Response()
    resp.status_code = status_code
    if json_data is not None:
        resp._content = json.dumps(json_data).encode("utf-8")
        resp.headers["content-type"] = "application/json"
    else:
        resp._content = text.encode("utf-8")
    return resp


def _make_tenant() -> ConfigurationModels.Systems.Elastic.Tenant:
    setup = ConfigurationModels.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.test:5601",
        elasticsearch_url="https://es.test:9200",
        api_key="test-key",
        space="default",
    )
    return ConfigurationModels.Systems.Elastic.Tenant(
        name="test-tenant",
        description="test",
        deployment=DeploymentStrategy.ALWAYS,
        setup=setup,
    )


def _make_rule(rule_id: str = "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c2d90", status: str = "STAGING") -> DetectionRule:
    raw = {
        "name": "Test Rule",
        "metadata": {
            "uuid": rule_id,
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
            "author": "Author",
        },
        "description": "Test description",
        "techniques": [],
        "response": {"alert_severity": "High"},
        "configurations": {
            "elastic": {
                "enabled": True,
                "schema": "platform::elastic::1.0",
                "status": status,
                "type": "query",
                "query": "process.name: *",
                "index": ["logs-*"],
            }
        },
    }
    from opentide.loading.rule_loader import load_rule_from_dict

    return load_rule_from_dict(raw)


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_create_rule_on_404(mock_checks) -> None:
    tenant = _make_tenant()
    rule = _make_rule()
    batch = MagicMock(rules=[rule])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with patch.object(client.session, "get") as mock_get, patch.object(client.session, "post") as mock_post:
        mock_get.return_value = _mock_response(404, {"message": "Not found"})
        mock_post.return_value = _mock_response(200, {"rule_id": rule.metadata.uuid})

        deployer = ElasticDeploy()
        deployer.deploy_mdr(batch, client, tenant)

        mock_get.assert_called_once()
        mock_post.assert_called_once()
        sent_body = mock_post.call_args[1]["json"]
        assert sent_body["rule_id"] == rule.metadata.uuid
        assert sent_body["enabled"] is True


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_update_rule_on_200_preserves_fields(mock_checks) -> None:
    tenant = _make_tenant()
    rule = _make_rule()
    batch = MagicMock(rules=[rule])

    remote_rule = {
        "rule_id": rule.metadata.uuid,
        "type": "query",
        "actions": [{"id": "remote-action"}],
        "exceptions_list": [{"id": "remote-exc"}],
        "timeline_id": "remote-timeline-id",
    }

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with patch.object(client.session, "get") as mock_get, patch.object(client.session, "put") as mock_put:
        mock_get.return_value = _mock_response(200, remote_rule)
        mock_put.return_value = _mock_response(200, {"rule_id": rule.metadata.uuid})

        deployer = ElasticDeploy()
        deployer.deploy_mdr(batch, client, tenant)

        mock_put.assert_called_once()
        sent_body = mock_put.call_args[1]["json"]
        assert sent_body["actions"] == [{"id": "remote-action"}]
        assert sent_body["exceptions_list"] == [{"id": "remote-exc"}]
        assert sent_body["timeline_id"] == "remote-timeline-id"


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_type_change_recreates_rule(mock_checks) -> None:
    tenant = _make_tenant()
    rule = _make_rule()  # type query
    batch = MagicMock(rules=[rule])

    remote_rule = {
        "rule_id": rule.metadata.uuid,
        "type": "threshold",  # different type
        "actions": [{"id": "remote-action"}],
    }

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with patch.object(client.session, "get") as mock_get, patch.object(client.session, "delete") as mock_del, patch.object(client.session, "post") as mock_post:
        mock_get.return_value = _mock_response(200, remote_rule)
        mock_del.return_value = _mock_response(200, {})
        mock_post.return_value = _mock_response(200, {"rule_id": rule.metadata.uuid})

        deployer = ElasticDeploy()
        deployer.deploy_mdr(batch, client, tenant)

        mock_del.assert_called_once()
        mock_post.assert_called_once()
        sent_body = mock_post.call_args[1]["json"]
        assert sent_body["actions"] == [{"id": "remote-action"}]


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_refuses_prebuilt_rule(mock_checks) -> None:
    tenant = _make_tenant()
    rule = _make_rule()
    batch = MagicMock(rules=[rule])

    remote_prebuilt = {
        "rule_id": rule.metadata.uuid,
        "type": "query",
        "immutable": True,
    }

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with patch.object(client.session, "get") as mock_get, patch.object(client.session, "put") as mock_put:
        mock_get.return_value = _mock_response(200, remote_prebuilt)

        deployer = ElasticDeploy()
        deployer.deploy_mdr(batch, client, tenant)

        mock_put.assert_not_called()


def test_deploy_delete_rule_404_treated_as_success() -> None:
    tenant = _make_tenant()
    rule = _make_rule(status="REMOVED")
    batch = MagicMock(rules=[rule])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with patch.object(client.session, "delete") as mock_del:
        mock_del.return_value = _mock_response(404, {"message": "Rule not found"})

        deployer = ElasticDeploy()
        # Should not raise exception
        deployer.deploy_mdr(batch, client, tenant)
        mock_del.assert_called_once()


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_rule_error_400_continues_batch(mock_checks) -> None:
    tenant = _make_tenant()
    rule1 = _make_rule("rule-1")
    rule2 = _make_rule("rule-2")
    batch = MagicMock(rules=[rule1, rule2])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with patch.object(client.session, "get") as mock_get, patch.object(client.session, "post") as mock_post:
        mock_get.return_value = _mock_response(404)
        mock_post.side_effect = [
            _mock_response(400, text="Bad request"),
            _mock_response(200, json_data={"rule_id": "rule-2"}),
        ]

        deployer = ElasticDeploy()
        deployer.deploy_mdr(batch, client, tenant)

        # Batch continued to second rule
        assert mock_post.call_count == 2
