"""Tests for schema generation entrypoint."""

from __future__ import annotations

from unittest.mock import patch


def test_schema_run_invokes_pipeline() -> None:
    from opentide.generation import schema

    with (
        patch("opentide.generation.schema.export_all_registered_schemas") as mock_export,
        patch("opentide.generation.schema.generate_model_schema", return_value={"type": "object"}),
        patch("opentide.generation.schema.export_opentide_router") as mock_router,
    ):
        schema.run()
    mock_export.assert_called_once()
    mock_router.assert_called_once()
