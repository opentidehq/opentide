"""Diagram graph primitives."""

from __future__ import annotations

from dataclasses import dataclass

from opentide.documentation.diagram.sanitize import sanitize_identifier, sanitize_label


@dataclass(frozen=True)
class Node:
    """Flowchart node."""

    identifier: str
    label: str

    def render(self) -> str:
        return f'{sanitize_identifier(self.identifier)}["{sanitize_label(self.label)}"]'


@dataclass(frozen=True)
class Edge:
    """Flowchart edge."""

    source: str
    target: str
    label: str | None = None

    def render(self) -> str:
        source = sanitize_identifier(self.source)
        target = sanitize_identifier(self.target)
        if self.label:
            return f"{source} -->|{sanitize_label(self.label)}| {target}"
        return f"{source} --> {target}"
