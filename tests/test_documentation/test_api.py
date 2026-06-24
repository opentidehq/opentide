"""Programmatic documentation API."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.documentation import api
from opentide.documentation.types import DocumentFlavor
from opentide.models.rule import DetectionRule


def test_render_rule_delegates_to_renderer(rule_payload: dict) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    with (
        patch.object(api, "_context") as mock_ctx,
        patch.object(api, "build_catalog") as mock_catalog,
        patch.object(api, "render_rule_page", return_value="# Rule") as mock_render,
    ):
        mock_ctx.return_value = MagicMock()
        mock_catalog.return_value = MagicMock()
        result = api.render_rule(rule, flavor=DocumentFlavor.github)
    assert result == "# Rule"
    mock_render.assert_called_once()


def test_write_all_counts_and_index(rule_payload: dict) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    catalog = MagicMock()
    catalog.rules = [MagicMock(model=rule, name="Rule", uuid=rule.metadata.uuid)]
    catalog.objectives = []
    catalog.threats = []
    ctx = MagicMock()
    pub = MagicMock()
    with (
        patch.object(api, "_context", return_value=ctx),
        patch.object(api, "build_catalog", return_value=catalog),
        patch.object(api, "targets", return_value=pub),
        patch.object(api, "render_rule_page", return_value="body"),
        patch.object(api, "page_path", return_value=MagicMock()),
        patch.object(api, "write_page") as mock_write,
        patch.object(api, "write_index") as mock_index,
    ):
        counts = api.write_all(include_index=True)
    assert counts["rules"] == 1
    mock_write.assert_called_once()
    mock_index.assert_called_once()


def test_write_rules_uses_provided_context(rule_payload: dict) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    catalog = MagicMock()
    catalog.rules = [MagicMock(model=rule, name="Rule", uuid=rule.metadata.uuid)]
    ctx = MagicMock()
    pub = MagicMock()
    with (
        patch.object(api, "targets", return_value=pub),
        patch.object(api, "render_rule_page", return_value="body"),
        patch.object(api, "page_path", return_value=MagicMock()),
        patch.object(api, "write_page") as mock_write,
    ):
        count = api.write_rules(ctx=ctx, catalog=catalog)
    assert count == 1
    mock_write.assert_called_once()


def test_render_objective_and_threat() -> None:
    with (
        patch.object(api, "_context") as mock_ctx,
        patch.object(api, "build_catalog") as mock_catalog,
        patch.object(api, "render_objective_page", return_value="# Objective") as mock_obj,
        patch.object(api, "render_threat_page", return_value="# Threat") as mock_threat,
    ):
        mock_ctx.return_value = MagicMock()
        mock_catalog.return_value = MagicMock()
        objective = MagicMock()
        threat = MagicMock()
        assert api.render_objective(objective).startswith("# Objective")
        assert api.render_threat(threat).startswith("# Threat")
    mock_obj.assert_called_once()
    mock_threat.assert_called_once()


def test_write_objectives_and_threats() -> None:
    ctx = MagicMock()
    pub = MagicMock()
    record = MagicMock(name="Item", uuid="u1", model=MagicMock())
    catalog = MagicMock(objectives=[record], threats=[record])
    with (
        patch.object(api, "targets", return_value=pub),
        patch.object(api, "render_objective_page", return_value="obj"),
        patch.object(api, "render_threat_page", return_value="threat"),
        patch.object(api, "page_path", return_value=MagicMock()),
        patch.object(api, "write_page") as mock_write,
    ):
        assert api.write_objectives(ctx=ctx, catalog=catalog) == 1
        assert api.write_threats(ctx=ctx, catalog=catalog) == 1
    assert mock_write.call_count == 2
