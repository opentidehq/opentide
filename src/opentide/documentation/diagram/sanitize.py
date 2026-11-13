"""Make object names safe inside Mermaid labels without changing what they say.

Names are written inside quoted labels (``["..."]``), where Mermaid accepts
brackets and parentheses as text. What it does not accept is escaped with
Mermaid's entity codes (``#quot;``), which every supported release decodes,
so ``Gather (Azure) "victim" data`` keeps its punctuation instead of losing it.
"""

from __future__ import annotations

#: ``#`` first: it starts every entity code written after it.
_NODE_ENTITIES = (
    ("#", "#35;"),
    ('"', "#quot;"),
    ("<", "#lt;"),
    (">", "#gt;"),
    ("`", "#96;"),
)
#: Edge text is quoted too (``-->|"label"|``), and also ends at a pipe. Quoting is
#: what Mermaid 8 accepts: it refuses entity codes for brackets in unquoted text.
_EDGE_ENTITIES = (*_NODE_ENTITIES, ("|", "#124;"))

#: Characters per label line before it wraps.
LABEL_WIDTH = 26


def escape(text: str, entities: tuple[tuple[str, str], ...] = _NODE_ENTITIES) -> str:
    """*text* on one line with Mermaid's reserved characters as entity codes."""
    escaped = " ".join(text.split())
    for raw, entity in entities:
        escaped = escaped.replace(raw, entity)
    return escaped


def node_label(text: str, *, width: int = LABEL_WIDTH) -> str:
    """A quoted-label body: escaped, wrapped with ``<br>`` every *width* characters.

    A *width* of 0 keeps the label on one line.
    """
    lines = wrap(text, width) if width else [" ".join(text.split())]
    return "<br>".join(escape(line) for line in lines) or "-"


def edge_label(text: str) -> str:
    """The body of a quoted edge label (``-->|"label"|``)."""
    return escape(text, _EDGE_ENTITIES)


def wrap(text: str, width: int) -> list[str]:
    """Greedy word wrap; a single word longer than *width* keeps its own line."""
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) <= width:
            current = f"{current} {word}"
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines
