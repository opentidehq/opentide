"""Detection rule documentation export."""

from __future__ import annotations

from opentide.documentation.rule_export import document_detection_rule
from opentide.models.metadata import ObjectMetadata
from opentide.models.platform import RuleConfigurations, SentinelConfig
from opentide.models.rule import DetectionRule


def test_document_detection_rule_renders_platform_query(metadata: dict) -> None:
    rule = DetectionRule(
        name="Doc rule",
        metadata=ObjectMetadata.model_validate(metadata),
        description="Rule description",
        configurations=RuleConfigurations(
            sentinel=SentinelConfig(
                enabled=True,
                name="S",
                platform_schema="platform::sentinel::1.0",
                status="STAGING",
                query="SecurityEvent | take 1",
                scheduling={"frequency": "PT1H", "lookback": "PT2H"},
                alert={"title": "T", "suppression": False},
            )
        ),
    )
    doc = document_detection_rule(rule)
    assert "# Doc rule" in doc
    assert "SecurityEvent" in doc
    assert "## Platform configurations" in doc
