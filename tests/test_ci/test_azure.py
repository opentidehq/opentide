"""Azure CI template generation tests."""

from __future__ import annotations

from opentide.ci.azure import render_azure
from opentide.ci.models import CiRenderOptions


def test_render_azure_includes_validate_stage() -> None:
    options = CiRenderOptions(ci="azure", platforms=["sentinel"])
    content = render_azure(options)
    assert "trigger:" in content
    assert "Validate" in content


def test_render_azure_omits_promote_when_no_steps() -> None:
    options = CiRenderOptions(ci="azure", promotion=True)
    content = render_azure(options)
    assert "stage: Promote" not in content
