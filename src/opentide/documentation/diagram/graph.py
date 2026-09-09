"""Diagram graph primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from opentide.documentation.diagram.sanitize import sanitize_identifier, wrap_label

NodeShape = Literal["rect", "hex", "stadium", "circle"]


@dataclass(frozen=True)
class Node:
    """Flowchart node."""

    identifier: str
    label: str
    shape: NodeShape = "rect"

    def render(self) -> str:
        ident = sanitize_identifier(self.identifier)
        label = wrap_label(self.label)
        if self.shape == "hex":
            return f'{ident}{{{{"{label}"}}}}'
        if self.shape == "stadium":
            return f'{ident}(["{label}"])'
        if self.shape == "circle":
            return f'{ident}(("{label}"))'
        return f'{ident}["{label}"]'


@dataclass(frozen=True)
class Edge:
    """Flowchart edge."""

    source: str
    target: str
    label: str | None = None
    bidirectional: bool = False

    def render(self) -> str:
        source = sanitize_identifier(self.source)
        target = sanitize_identifier(self.target)
        arrow = "<-->" if self.bidirectional else "-->"
        if self.label:
            return f"{source} {arrow}|{wrap_label(self.label, limit=18)}| {target}"
        return f"{source} {arrow} {target}"
