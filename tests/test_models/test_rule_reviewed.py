"""RFC 0008: optional metadata.reviewed on rule::1.1."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from opentide.generation.pydantic_schemas import generate_schema_for_identifier
from opentide.generation.pydantic_skeleton import render_model_template
from opentide.loading.object_loader import load_object
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.metadata import ObjectMetadata
from opentide.models.review import parse_review_instant, unreviewed_reason
from opentide.models.rule import DetectionRule, DetectionRule_v1_1
from opentide.models.schema_registry import latest_identifier, resolve_model
from opentide.models.vocab_pins import get_pins


def _metadata(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.1",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }
    payload.update(overrides)
    return payload


def _rule(**metadata_overrides: Any) -> dict[str, Any]:
    return {
        "name": "Reviewed rule",
        "description": "desc",
        "metadata": _metadata(**metadata_overrides),
    }


def test_rule_11_accepts_date_and_datetime() -> None:
    dated = DetectionRule_v1_1.model_validate(_rule(reviewed="2026-09-01"))
    stamped = DetectionRule_v1_1.model_validate(_rule(reviewed="2026-09-01T15:04:05Z"))
    assert dated.metadata.reviewed == "2026-09-01"
    assert stamped.metadata.reviewed == "2026-09-01T15:04:05Z"
    assert parse_review_instant("2026-09-01") == datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert parse_review_instant("2026-09-01T15:04:05Z") == datetime(
        2026, 9, 1, 15, 4, 5, tzinfo=timezone.utc
    )


def test_rule_11_omitted_reviewed_is_valid() -> None:
    rule = DetectionRule_v1_1.model_validate(_rule())
    assert rule.metadata.reviewed is None
    assert rule.schema_identifier() == "rule::1.1"


def test_rule_11_rejects_a_bad_review_date() -> None:
    with pytest.raises(ValidationError, match="ISO 8601"):
        DetectionRule_v1_1.model_validate(_rule(reviewed="yesterday"))


def test_rule_10_threat_and_objective_reject_reviewed() -> None:
    with pytest.raises(ValidationError, match="reviewed"):
        DetectionRule.model_validate(_rule(schema="rule::1.0", reviewed="2026-09-01"))
    for schema in ("rule::1.0", "threat::1.0", "objective::1.0"):
        with pytest.raises(ValidationError, match="reviewed"):
            ObjectMetadata.model_validate(_metadata(schema=schema, reviewed="2026-09-01"))


def test_loader_routes_schema_identifier() -> None:
    current = load_rule_from_dict(_rule(reviewed="2026-09-01"))
    legacy = load_rule_from_dict(_rule(schema="rule::1.0"))
    assert isinstance(current, DetectionRule_v1_1)
    assert type(legacy) is DetectionRule
    loaded = load_object(_rule(reviewed="2026-09-01T00:00:00+00:00"))
    assert isinstance(loaded, DetectionRule_v1_1)
    assert resolve_model("rule::1.1") is DetectionRule_v1_1
    assert latest_identifier("rule") == "rule::1.1"


def test_pins_match_rule_10() -> None:
    assert get_pins("rule::1.1") == get_pins("rule::1.0")
    assert get_pins("rule::1.1")["severity"] == "severity::1.0"


def test_generated_schema_keeps_reviewed_on_11_only() -> None:
    current = generate_schema_for_identifier("rule::1.1", enrich=False)
    legacy = generate_schema_for_identifier("rule::1.0", enrich=False)
    assert "reviewed" in json.dumps(current)
    assert "reviewed" not in json.dumps(legacy)
    assert current["properties"]["metadata"]["properties"]["schema"]["const"] == "rule::1.1"
    assert legacy["properties"]["metadata"]["properties"]["schema"]["const"] == "rule::1.0"


def test_template_leaves_reviewed_absent() -> None:
    text = render_model_template(DetectionRule_v1_1)
    assert "schema: rule::1.1" in text
    assert "#reviewed:" in text
    loaded = yaml.safe_load(text)
    assert "reviewed" not in loaded["metadata"]


def test_unreviewed_predicate_boundaries() -> None:
    now = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    window = timedelta(days=90)
    assert unreviewed_reason("rule::1.0", None, now=now, window=window) == "schema"
    assert unreviewed_reason("rule::1.1", None, now=now, window=window) == "absent"
    assert unreviewed_reason("rule::1.1", "2026-01-01", now=now, window=window) == "stale"
    cutoff = now - window
    exact = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    earlier = (cutoff - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert unreviewed_reason("rule::1.1", exact, now=now, window=window) is None
    assert unreviewed_reason("rule::1.1", earlier, now=now, window=window) == "stale"
    assert unreviewed_reason("objective::1.0", None, now=now, window=window) is None
