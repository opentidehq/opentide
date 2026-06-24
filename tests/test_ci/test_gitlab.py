"""GitLab CI template generation tests."""

from __future__ import annotations

from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions


def test_render_gitlab_includes_stages() -> None:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"])
    content = render_gitlab(options)
    assert "stages:" in content
    assert "validate" in content
