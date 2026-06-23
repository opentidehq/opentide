"""Mindmap diagram rendering."""

from __future__ import annotations

from opentide.documentation.diagram.sanitize import sanitize_label
from opentide.documentation.format.protocol import MarkdownFormatter


def build_mindmap(formatter: MarkdownFormatter, root: str, branches: dict[str, list[str]]) -> str:
    """Build a basic mermaid mindmap."""
    lines = ["mindmap", f"  root(({sanitize_label(root)}))"]
    for branch, leaves in branches.items():
        lines.append(f"    {sanitize_label(branch)}")
        for leaf in leaves:
            lines.append(f"      {sanitize_label(leaf)}")
    diagram = "\n".join(lines)
    return formatter.mermaid_fence(formatter.diagram_mindmap(diagram))
