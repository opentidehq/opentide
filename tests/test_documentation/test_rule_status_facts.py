"""Rule pages show what deploy reads, never a model default (the 525-rule `STAGING` page).

``DetectionRule.status`` defaulted to ``STAGING`` and ``severity`` to
``Informational``, and the docs rendered them whether or not they were
authored, so every page and the rules index said ``STAGING`` /
``Informational`` for rules in ``PRODUCTION`` with Critical alerts. Promotion
rewrites the platform blocks' statuses, never a rule-level one, so even an
authored rule-level ``status`` drifted at the first promotion.
"""

from __future__ import annotations

from typing import Any

import pytest

from opentide._models.rule import DetectionRule
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.parts.sections import render_rule_status
from opentide.documentation.publish.index import _extra_cells
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope

_SENTINEL = {
    "status": "PRODUCTION",
    "query": "SecurityEvent",
    "scheduling": {"frequency": "1h"},
    "alert": {},
}


def _rule(metadata: dict[str, Any], **fields: Any) -> DetectionRule:
    return DetectionRule.from_yaml_dict(
        {
            "name": "Rule",
            "metadata": {**metadata, "schema": "rule::1.0"},
            "description": "d",
            **fields,
        }
    )


def test_an_unauthored_status_and_severity_stay_unset(metadata: dict[str, Any]) -> None:
    rule = _rule(metadata)
    assert rule.status is None
    assert rule.severity is None
    assert rule.platform_statuses == {}
    assert rule.displayed_severity is None
    assert render_rule_status(rule, formatter_for(DocumentFlavor.generic)) == ""


def test_the_page_shows_each_block_status_and_the_alert_severity(
    metadata: dict[str, Any],
) -> None:
    rule = _rule(
        metadata,
        # A rule-level status left behind by an earlier promotion.
        status="STAGING",
        response={"alert_severity": "Critical"},
        configurations={
            "sentinel": _SENTINEL,
            "splunk": {"status": "STAGING", "query": "index=main"},
        },
    )
    page = render_rule_status(rule, formatter_for(DocumentFlavor.generic))
    assert "Status (sentinel)" in page and "`PRODUCTION`" in page
    assert "Status (splunk)" in page
    assert "`Critical`" in page
    assert "Informational" not in page
    assert page.count("`STAGING`") == 1  # splunk's block, not the rule-level value


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({}, None),
        ({"severity": "High"}, "High"),
        ({"severity": "High", "response": {"alert_severity": "Low"}}, "Low"),
        ({"response": {}}, "Informational"),  # what deploy sends for an empty response
    ],
)
def test_the_displayed_severity_is_what_the_rule_states(
    metadata: dict[str, Any], fields: dict[str, Any], expected: str | None
) -> None:
    assert _rule(metadata, **fields).displayed_severity == expected


def test_the_rules_index_row_uses_the_derived_values(metadata: dict[str, Any]) -> None:
    rule = _rule(
        metadata,
        response={"alert_severity": "High"},
        configurations={
            "sentinel": _SENTINEL,
            "splunk": {"status": "STAGING", "query": "index=main"},
        },
    )
    record = DocumentRecord(
        object_type=DocumentScope.rules, uuid=rule.metadata.uuid, name="Rule", model=rule
    )
    assert _extra_cells(record) == ["PRODUCTION, STAGING", "High"]
    bare = DocumentRecord(
        object_type=DocumentScope.rules,
        uuid=rule.metadata.uuid,
        name="Rule",
        model=_rule(metadata),
    )
    assert _extra_cells(bare) == ["", ""]
