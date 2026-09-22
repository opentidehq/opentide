"""Tests for validation services."""

from __future__ import annotations

from opentide.cli.context import CliContext
from opentide.cli.services.validation import validate_query_platform


def test_validate_query_platform_rejects_crowdstrike() -> None:
    """Unsupported is still exit 1, but reported through the usual envelope."""
    ctx = CliContext(json_output=True)
    result = validate_query_platform(ctx, "crowdstrike")
    assert result["supported"] is False
    assert result["valid"] is None
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
