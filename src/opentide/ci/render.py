"""Dispatch CI rendering to platform-specific renderers."""

from __future__ import annotations

from opentide.ci.azure import render_azure
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions


def render_ci(options: CiRenderOptions) -> dict[str, str]:
    """Return generated CI file path and content for the selected platform."""
    if options.ci == "github":
        content = render_github(options)
    elif options.ci == "gitlab":
        content = render_gitlab(options)
    elif options.ci == "azure":
        content = render_azure(options)
    else:
        msg = f"CI generation is not supported for platform: {options.ci}"
        raise ValueError(msg)

    return {options.output_path(): content}
