"""Template renderer smoke tests."""

from __future__ import annotations


def test_template_renderer_run_smoke() -> None:
    from opentide.generation.template_renderer import run as template_renderer_run

    template_renderer_run()
