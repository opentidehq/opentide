"""Indent-safe helpers for CI pipeline text templates.

``textwrap.dedent`` over f-strings that already contain pre-indented fragments
strips the wrong common indent and emits invalid YAML (issue #163).
"""

from __future__ import annotations


def indent(text: str, spaces: int) -> str:
    """Indent every non-empty line by ``spaces`` spaces."""
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def join_blocks(*blocks: str) -> str:
    """Join non-empty blocks with a blank line."""
    return "\n".join(block.rstrip() for block in blocks if block and block.strip())
