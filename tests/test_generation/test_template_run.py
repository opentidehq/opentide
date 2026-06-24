"""Tests for template generation entrypoint."""

from __future__ import annotations

from unittest.mock import patch


def test_template_run_invokes_renderer() -> None:
    from opentide.generation import template

    with patch("opentide.generation.template_renderer.run") as mock_run:
        template.run()
    mock_run.assert_called_once()
