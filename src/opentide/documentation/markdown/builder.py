"""Small markdown builder helpers."""

from __future__ import annotations


def join_blocks(blocks: list[str]) -> str:
    """Join non-empty markdown blocks with blank lines."""
    return "\n\n".join(block.strip() for block in blocks if block and block.strip())
