"""Text helpers for CI pipeline files.

``textwrap.dedent`` over f-strings that already contain pre-indented fragments
strips the wrong common indent and emits invalid YAML (issue #163), so the
string-built renderers indent with :func:`indent`. The GitLab renderer builds
its pipeline as data and writes it with :func:`dump_pipeline` instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import yaml


def indent(text: str, spaces: int) -> str:
    """Indent every non-empty line by ``spaces`` spaces."""
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def join_blocks(*blocks: str) -> str:
    """Join non-empty blocks with a blank line."""
    return "\n".join(block.rstrip() for block in blocks if block and block.strip())


class _PipelineDumper(yaml.SafeDumper):
    """Indents sequences under their key, as CI documentation writes them."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        super().increase_indent(flow, False)

    def choose_scalar_style(self) -> str:
        """``"0"`` rather than ``'0'``, as GitLab's documentation quotes, unless that escapes."""
        style = super().choose_scalar_style()
        value = self.event.value if isinstance(self.event, yaml.ScalarEvent) else ""
        if style == "'" and '"' not in value and "\\" not in value:
            return '"'
        return style


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    """A multi-line script as a ``|`` block, so it reads as the shell it is."""
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_PipelineDumper.add_representer(str, _represent_str)

#: Never fold a long command onto two lines: folding is valid YAML, but the
#: file is read by people looking for the command they saw in a job log.
_NO_FOLDING = 1_000_000


def dump_pipeline(document: Mapping[str, Any]) -> str:
    """*document* as YAML, a blank line between top-level keys.

    The text is parsed back and compared with *document*: a value YAML would
    read differently (``yes``, ``1.0``, ``: `` in a command) is quoted by the
    dumper, and anything else is a bug that must not reach a pipeline file.
    """
    text = yaml.dump(
        dict(document),
        Dumper=_PipelineDumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=_NO_FOLDING,
    )
    if yaml.safe_load(text) != dict(document):
        raise ValueError("the pipeline does not survive a YAML round trip")
    lines: list[str] = []
    for line in text.splitlines():
        # Top-level keys start in column 0; block scalars and nested keys never do.
        if lines and line and not line[0].isspace() and not line.startswith("-"):
            lines.append("")
        lines.append(line)
    return "\n".join(lines) + "\n"
