"""Write generated CI pipeline files to a client repository."""

from __future__ import annotations

from pathlib import Path

from opentide.ci.models import CiRenderOptions
from opentide.ci.render import render_ci


def write_ci(target: Path, options: CiRenderOptions) -> list[str]:
    """Render and write CI files; returns written relative paths."""
    written: list[str] = []
    for rel_path, content in render_ci(options).items():
        dest = target / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        written.append(rel_path)
    return written
