"""Tests for CI render dispatch."""

from __future__ import annotations

import pytest

from opentide.ci.models import CiRenderOptions
from opentide.ci.render import render_ci


def test_render_ci_unknown_platform_raises() -> None:
    options = CiRenderOptions(ci="circleci")
    with pytest.raises(ValueError, match="not supported"):
        render_ci(options)
