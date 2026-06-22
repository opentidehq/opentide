"""Template generation — TemplateRenderer entry point."""

from __future__ import annotations


def run() -> None:
    """Generate YAML templates from Pydantic-backed pipeline."""
    from opentide.generation.template_renderer import run as renderer_run

    renderer_run()
