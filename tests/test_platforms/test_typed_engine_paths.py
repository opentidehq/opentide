"""Edge paths the type checker surfaced in the platform engines."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from opentide.deployment.external_ids import ExternalIdAction
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels, DeploymentBatch, batch_tenant


def _rule(metadata: dict[str, Any], **body: Any) -> Any:
    return load_rule_from_dict({"name": "Rule", "metadata": metadata, "description": "d", **body})


def test_a_rule_without_configurations_names_itself(metadata: dict[str, Any]) -> None:
    """Engines read ``rule.configurations.<platform>`` and raised on ``None``."""
    rule = _rule(metadata)
    with pytest.raises(ValueError, match=r"Rule .* \(Rule\) has no configurations block"):
        rule.platform_configs()


def test_a_rule_without_response_has_the_default_alert_severity(metadata: dict[str, Any]) -> None:
    assert _rule(metadata).alert_severity == "Informational"


@pytest.mark.parametrize("kind", ["update", "delete"])
def test_an_update_or_delete_needs_the_recorded_id(kind: str) -> None:
    with pytest.raises(ValueError, match=f"cannot {kind} a rule without its recorded external id"):
        ExternalIdAction(kind, None).known_id()  # ty: ignore[invalid-argument-type]
    assert ExternalIdAction("delete", "42").known_id() == "42"


def test_batch_tenant_refuses_another_platforms_tenant() -> None:
    setup = ConfigurationModels.Systems.Elastic.Tenant.Setup(
        ssl=True, url="https://k", elasticsearch_url="", api_key="k", space="default"
    )
    elastic = ConfigurationModels.Systems.Elastic.Tenant(name="e", description="", setup=setup)
    batch = DeploymentBatch(tenant=elastic, rules=[])

    assert batch_tenant(batch, ConfigurationModels.Systems.Elastic.Tenant) is elastic
    with pytest.raises(TypeError, match=r"expected a .*Splunk\.Tenant tenant, got .*Elastic"):
        batch_tenant(batch, ConfigurationModels.Systems.Splunk.Tenant)


def test_engines_accept_rule_objects_and_an_empty_selection(
    metadata: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defender's deployer looked up ``Opentide.Rules[rule]`` with rule objects, and
    its validator read ``mdr_deployment[0]``, an IndexError on an empty selection."""
    from opentide.platforms import plugins

    rule = _rule(metadata)
    registry = SimpleNamespace(Rules={str(rule.metadata.uuid): rule})
    monkeypatch.setattr("opentide.core.registry.Opentide", registry)

    assert plugins.resolve_rules([rule]) == [rule]
    assert plugins.resolve_rules([str(rule.metadata.uuid)]) == [rule]
    assert plugins.resolve_rules([]) == []


def test_an_azure_error_without_a_body_falls_back_to_the_generic_message() -> None:
    from opentide.platforms.sentinel.validator import _inner_message

    with pytest.raises(KeyError):
        _inner_message(SimpleNamespace(error=None))  # ty: ignore[invalid-argument-type]
