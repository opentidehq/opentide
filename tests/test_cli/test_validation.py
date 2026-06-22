"""Tests for validation services."""

from __future__ import annotations

import pytest

from opentide.cli.context import CliContext
from opentide.cli.services.validation import validate_query_platform


def test_validate_query_platform_rejects_crowdstrike() -> None:
    ctx = CliContext(json_output=True)
    with pytest.raises(SystemExit) as exc:
        validate_query_platform(ctx, "crowdstrike")
    assert exc.value.code == 1
