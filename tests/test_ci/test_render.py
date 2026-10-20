"""Tests for CI render dispatch."""

from __future__ import annotations

import pytest

from opentide.ci.models import CiRenderOptions
from opentide.ci.render import render_ci


def test_render_ci_unknown_platform_raises() -> None:
    options = CiRenderOptions(ci="circleci")
    with pytest.raises(ValueError, match="not supported"):
        render_ci(options)


@pytest.mark.parametrize("ci", ["github", "gitlab", "azure"])
@pytest.mark.parametrize("staging", [True, False], ids=["staging", "no-staging"])
def test_no_generated_file_uses_a_removed_deployment_plan(ci: str, staging: bool) -> None:
    """``--plan`` and ``DEPLOYMENT_PLAN`` were removed in 0.17.0: a run names its strategy."""
    options = CiRenderOptions(
        ci=ci,
        platforms=["sentinel", "splunk", "crowdstrike"],
        staging=staging,
        explorer_pages=True,
        inflight=True,
        sharing=True,
    )
    files = render_ci(options)
    assert files
    for path, content in files.items():
        assert "--plan" not in content, path
        assert "DEPLOYMENT_PLAN" not in content, path
        assert "opentide deploy --dry-run --strategy RELEASE" in content, path
        assert "opentide deploy --strategy RELEASE --skip-unconfigured" in content, path
        assert ("opentide deploy --strategy PREVIEW --skip-unconfigured" in content) is staging
        for line in content.splitlines():
            if "opentide deploy --" in line:
                assert "--strategy" in line, (path, line)
