"""Tests for schema generation entrypoint."""

from __future__ import annotations

from unittest.mock import patch


def test_schema_run_invokes_pipeline() -> None:
    from opentide.generation import schema

    with patch("opentide.generation.schema_pipeline.run") as mock_run:
        schema.run()
    mock_run.assert_called_once()
