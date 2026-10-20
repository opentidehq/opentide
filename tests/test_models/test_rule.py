"""DetectionRule model behaviour."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from opentide.models.metadata import ObjectMetadata
from opentide.models.rule import DetectionRule


def test_detection_rule_from_yaml_and_delegation(metadata: dict[str, Any]) -> None:
    payload = {
        "name": "Test rule",
        "metadata": metadata,
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": ["T1059"],
        "platforms": {},
    }
    rule = DetectionRule.from_yaml_dict(payload, file=Path("rule.yaml"))
    assert rule.file == Path("rule.yaml")
    assert rule.metadata.schema_id == "rule::1.0"

    registry = MagicMock()
    registry.Platforms = {"sentinel": MagicMock(deployer=MagicMock())}
    registry.validate_rule.return_value = MagicMock(ok=True, errors=[], warnings=[])
    registry.document_rule.return_value = "# doc"

    bound = rule.bind_registry(registry)
    bound.deploy("sentinel", dry_run=True)
    bound.validate()
    bound.document()
    bound.promote("PRODUCTION")

    result = bound.validate_query("crowdstrike")
    assert result.ok is False


def test_detection_rule_requires_registry(metadata: dict[str, Any]) -> None:
    rule = DetectionRule(
        name="R",
        metadata=ObjectMetadata.model_validate(metadata),
        description="d",
    )
    with pytest.raises(RuntimeError):
        rule.deploy("sentinel")


_CORPUS_SENTINEL_RULE = (
    Path(__file__).resolve().parents[1]
    / "fixtures/tide_corpus/current/Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
)


def _sentinel_rule(metadata: dict[str, Any], status: str = "STAGING") -> DetectionRule:
    """The corpus Sentinel rule under *metadata*, with its Sentinel status set to *status*."""
    import yaml

    data = yaml.safe_load(_CORPUS_SENTINEL_RULE.read_text(encoding="utf-8"))
    data["metadata"] = metadata
    data["configurations"]["sentinel"]["status"] = status
    return DetectionRule.from_yaml_dict(data)


def _bound(rule: DetectionRule) -> tuple[DetectionRule, MagicMock]:
    registry = MagicMock()
    registry.Platforms = {
        "sentinel": MagicMock(deployer=MagicMock(), validator=MagicMock()),
        "crowdstrike": MagicMock(deployer=MagicMock(), validator=MagicMock()),
    }
    return rule.bind_registry(registry), registry.Platforms["sentinel"].deployer.deploy


def test_detection_rule_deploy_and_validate_query_success(metadata: dict[str, Any]) -> None:
    from opentide.models.deployment_enums import StatusStrategy

    bound, deployer = _bound(_sentinel_rule(metadata))
    result = bound.deploy("sentinel", dry_run=False, strategies=["release"])
    assert result.dry_run is False
    assert bound.validate_query("sentinel").ok is True
    deployer.assert_called_once()
    assert deployer.call_args.args == (
        [str(bound.metadata.uuid)],
        (StatusStrategy.RELEASE,),
    )
    with pytest.raises(ValueError, match="not_a_platform"):
        bound.deploy("not_a_platform", dry_run=True)


@pytest.mark.parametrize(
    ("status", "run"),
    [
        ("STAGING", ("PREVIEW",)),
        ("PRODUCTION", ("RELEASE",)),
        ("REMOVED", ("RELEASE",)),
        ("DESIGN", ()),
    ],
)
def test_detection_rule_deploy_defaults_to_the_runs_that_deploy_its_status(
    metadata: dict[str, Any], status: str, run: tuple[str, ...]
) -> None:
    bound, deployer = _bound(_sentinel_rule(metadata, status))
    bound.deploy("sentinel")
    assert tuple(s.name for s in deployer.call_args.args[1]) == run


def test_detection_rule_deploy_without_a_platform_status_is_refused(
    metadata: dict[str, Any],
) -> None:
    """The rule has no CrowdStrike block, so no status says which runs deploy it."""
    bound, _ = _bound(_sentinel_rule(metadata))
    with pytest.raises(ValueError, match=r"has no crowdstrike status to deploy"):
        bound.deploy("crowdstrike")
    bound._registry.Platforms["crowdstrike"].deployer.deploy.assert_not_called()


def test_detection_rule_deploy_refuses_a_plan_name_as_a_strategy(
    metadata: dict[str, Any],
) -> None:
    bound, deployer = _bound(_sentinel_rule(metadata))
    with pytest.raises(ValueError, match="STAGING was a deployment plan, removed in 0.17.0"):
        bound.deploy("sentinel", strategies=["STAGING"])
    deployer.assert_not_called()
