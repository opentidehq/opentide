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


def test_detection_rule_deploy_and_validate_query_success(metadata: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(
        {
            "name": "Test rule",
            "metadata": metadata,
            "description": "desc",
            "status": "STAGING",
            "severity": "High",
            "techniques": ["T1059"],
            "platforms": {},
        }
    )
    registry = MagicMock()
    registry.Platforms = {
        "sentinel": MagicMock(deployer=MagicMock(), validator=MagicMock()),
    }
    bound = rule.bind_registry(registry)
    result = bound.deploy("sentinel", dry_run=False)
    assert result.dry_run is False
    assert bound.validate_query("sentinel").ok is True
    registry.Platforms["sentinel"].deployer.deploy.assert_called_once()
