"""Mindmap diagram builder."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.documentation.diagram.mindmap import build_mindmap


def test_build_mindmap_wraps_formatter_output() -> None:
    formatter = MagicMock()
    formatter.diagram_mindmap.side_effect = lambda diagram: diagram
    formatter.mermaid_fence.side_effect = lambda diagram: f"```mermaid\n{diagram}\n```"

    result = build_mindmap(
        formatter,
        root="Threat",
        branches={"Tactics": ["Execution", "Persistence"]},
    )

    assert "mindmap" in result
    assert "Threat" in result
    assert "Execution" in result
    formatter.mermaid_fence.assert_called_once()
