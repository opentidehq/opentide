"""Tests for ElasticClient and ElasticDeploy (RFC 0007 §4 & §5)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.deployer import ElasticDeploy
from opentide.platforms.elastic.es_checks import ElasticTenantError


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


def _make_rule(
    rule_id: str = "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c2d90", status: str = "STAGING"
) -> DetectionRule:
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
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
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
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "put") as mock_put,
    ):
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
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "delete") as mock_del,
        patch.object(client.session, "post") as mock_post,
    ):
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
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "put") as mock_put,
    ):
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
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _mock_response(404)
        mock_post.side_effect = [
            _mock_response(400, text="Bad request"),
            _mock_response(200, json_data={"rule_id": "rule-2"}),
        ]

        deployer = ElasticDeploy()
        deployer.deploy_mdr(batch, client, tenant)

        # Batch continued to second rule
        assert mock_post.call_count == 2


def _clear_deploy_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEPLOYMENT_ERROR_RAISED", raising=False)
    monkeypatch.delenv("DEPLOYMENT_WARNING_RAISED", raising=False)


def _esql_rule(rule_id: str, query: str) -> DetectionRule:
    raw = {
        "name": "ES|QL Rule",
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
                "status": "STAGING",
                "type": "esql",
                "query": query,
            }
        },
    }
    from opentide.loading.rule_loader import load_rule_from_dict

    return load_rule_from_dict(raw)


def test_deploy_esql_parse_error_skips_create(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    rule = _esql_rule("esql-bad", "FROM logs-* | WHER process.name == 'test'")
    batch = MagicMock(rules=[rule])
    client = ElasticClient(url=tenant.setup.url, elasticsearch_url=tenant.setup.elasticsearch_url)

    with (
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "get") as mock_get,
    ):
        mock_post.return_value = _mock_response(
            400,
            json_data={"error": {"type": "parsing_exception", "reason": "mismatched input 'WHER'"}},
        )
        ElasticDeploy().deploy_mdr(batch, client, tenant)
        mock_get.assert_not_called()
        assert mock_post.call_count == 1

    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"
    from opentide.cli.exit_codes import deployment_outcome

    assert deployment_outcome().failed is True


def test_deploy_unresolved_esql_index_still_creates(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    rule = _esql_rule("esql-new", "FROM logs-* | WHERE process.name == 'test'")
    batch = MagicMock(rules=[rule])
    client = ElasticClient(url=tenant.setup.url, elasticsearch_url=tenant.setup.elasticsearch_url)

    with (
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "get") as mock_get,
    ):
        mock_post.side_effect = [
            _mock_response(
                400,
                json_data={"error": {"type": "verification_exception", "reason": "Unknown index"}},
            ),
            _mock_response(200, json_data={"rule_id": rule.metadata.uuid}),
        ]
        mock_get.side_effect = [
            _mock_response(200, json_data={"indices": [], "aliases": [], "data_streams": []}),
            _mock_response(404, json_data={"message": "Not found"}),
        ]
        ElasticDeploy().deploy_mdr(batch, client, tenant)
        assert mock_post.call_count == 2

    assert os.environ.get("DEPLOYMENT_WARNING_RAISED") == "1"
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") is None


@pytest.mark.parametrize("get_status", [500, 502, 418])
@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_unexpected_get_status_fails_rule_not_silently(
    mock_checks, get_status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    batch = MagicMock(rules=[_make_rule("r1"), _make_rule("r2")])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "put") as mock_put,
    ):
        mock_get.return_value = _mock_response(get_status, text="boom")
        ElasticDeploy().deploy_mdr(batch, client, tenant)

        assert mock_get.call_count == 2
        mock_post.assert_not_called()
        mock_put.assert_not_called()
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"


@pytest.mark.parametrize("put_status", [404, 422, 500])
@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_failed_put_fails_rule_and_continues(
    mock_checks, put_status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    batch = MagicMock(rules=[_make_rule("r1"), _make_rule("r2")])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "put") as mock_put,
    ):
        mock_get.return_value = _mock_response(200, {"type": "query"})
        mock_put.return_value = _mock_response(put_status, text="nope")
        ElasticDeploy().deploy_mdr(batch, client, tenant)

        assert mock_put.call_count == 2
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_type_change_failed_delete_does_not_post(
    mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    batch = MagicMock(rules=[_make_rule("r1"), _make_rule("r2")])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "delete") as mock_delete,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _mock_response(200, {"type": "eql"})
        mock_delete.return_value = _mock_response(500, text="boom")
        ElasticDeploy().deploy_mdr(batch, client, tenant)

        assert mock_delete.call_count == 2
        mock_post.assert_not_called()
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_put_401_fails_the_tenant(mock_checks) -> None:
    tenant = _make_tenant()
    batch = MagicMock(rules=[_make_rule("r1"), _make_rule("r2")])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "put") as mock_put,
    ):
        mock_get.return_value = _mock_response(200, {"type": "query"})
        mock_put.return_value = _mock_response(401, text="unauthorized")
        with pytest.raises(Exception, match="HTTP 401"):
            ElasticDeploy().deploy_mdr(batch, client, tenant)
        assert mock_put.call_count == 1


def test_client_preview_uses_the_kibana_preview_route() -> None:
    """Kibana's route is DETECTION_ENGINE_RULES_PREVIEW = /api/detection_engine/rules/preview."""
    client = ElasticClient(url="https://kibana.test:5601", api_key="k", space="staging")
    with patch.object(client.session, "post") as mock_post:
        mock_post.return_value = _mock_response(200, {"logs": []})
        client.preview_rule({"rule_id": "x"}, timeframe_end="2026-09-25T11:10:00.000Z")
    assert mock_post.call_args[0][0] == (
        "https://kibana.test:5601/s/staging/api/detection_engine/rules/preview"
    )


@pytest.mark.parametrize("post_status", [401, 403])
@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_create_auth_error_fails_the_tenant(
    mock_checks, post_status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RFC 0007 §5: a 401 or 403 on the create POST stops the tenant, not just the rule."""
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    batch = MagicMock(rules=[_make_rule("r1"), _make_rule("r2")])

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _mock_response(404, {"message": "Not found"})
        mock_post.return_value = _mock_response(post_status, {"message": "missing privileges"})
        with pytest.raises(ElasticTenantError, match=f"HTTP {post_status}"):
            ElasticDeploy().deploy_mdr(batch, client, tenant)
        assert mock_post.call_count == 1


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_create_error_reports_kibana_message_and_continues(
    mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    batch = MagicMock(rules=[_make_rule("r1"), _make_rule("r2")])

    # Recorded at the deployer: loggers cached on first use bypass capture_logs.
    failed: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "opentide.platforms.elastic.deployer._deployment_error",
        lambda event, **fields: failed.append((event, fields)),
    )

    client = ElasticClient(url=tenant.setup.url, api_key=tenant.setup.api_key)
    with (
        patch.object(client.session, "get") as mock_get,
        patch.object(client.session, "post") as mock_post,
    ):
        mock_get.return_value = _mock_response(404, {"message": "Not found"})
        mock_post.side_effect = [
            _mock_response(422, {"statusCode": 422, "message": "invalid query"}),
            _mock_response(200, {"rule_id": "r2"}),
        ]
        ElasticDeploy().deploy_mdr(batch, client, tenant)

        assert mock_post.call_count == 2
    assert failed == [
        (
            "create_elastic_rule_failed",
            {"rule_id": "r1", "status_code": 422, "error": "invalid query"},
        )
    ]


@patch("opentide.platforms.elastic.deployer.run_elasticsearch_checks")
def test_deploy_create_401_through_deploy_fails_the_run(
    mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_deploy_flags(monkeypatch)
    tenant = _make_tenant()
    batch = MagicMock(tenant=tenant, rules=[_make_rule("r1"), _make_rule("r2")])
    monkeypatch.setattr(
        "opentide.platforms.elastic.deployer.without_legacy_external_ids",
        lambda rules, platform: rules,
    )
    monkeypatch.setattr(
        "opentide.platforms.elastic.deployer.TideDeployment",
        MagicMock(return_value=MagicMock(rule_deployment=[batch])),
    )
    with (
        patch("requests.Session.get") as mock_get,
        patch("requests.Session.post") as mock_post,
    ):
        mock_get.return_value = _mock_response(404, {"message": "Not found"})
        mock_post.return_value = _mock_response(401, {"message": "unauthorized"})
        ElasticDeploy().deploy(list(batch.rules), DeploymentStrategy.STAGING)

        assert mock_post.call_count == 1
    assert os.environ.get("DEPLOYMENT_ERROR_RAISED") == "1"


def test_find_managed_paginates_past_1000_rules() -> None:
    client = ElasticClient(url="https://kibana.test", api_key="k")
    page_1 = [{"rule_id": f"r-{i}"} for i in range(1000)]
    page_2 = [{"rule_id": f"r-{i}"} for i in range(1000, 2000)]
    page_3 = [{"rule_id": f"r-{i}"} for i in range(2000, 2691)]

    with patch.object(client.session, "get") as mock_get:
        mock_get.side_effect = [
            _mock_response(200, {"total": 2691, "data": page_1}),
            _mock_response(200, {"total": 2691, "data": page_2}),
            _mock_response(200, {"total": 2691, "data": page_3}),
        ]
        managed = client.find_managed("OpenTide")

    assert len(managed) == 2691
    assert mock_get.call_count == 3
    assert [call.kwargs["params"]["page"] for call in mock_get.call_args_list] == [1, 2, 3]
