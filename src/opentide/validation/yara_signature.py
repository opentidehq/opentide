"""``yara_signature_alias``: a YARA ``signature`` written out in its block (yara-1.0).

A platform ``yara`` block embeds a ``YaraSignature`` whose ``signature`` must be
its own text. Loading the YAML turns an alias into the anchored value, so the
check reads the composed node graph of the file: a node reached a second time
is an alias, and the first place it appears is its anchor.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from opentide.validation.issues import ValidationIssue

CODE = "yara_signature_alias"


#: Platforms whose own check reports the alias (HarfangLab, in ``validation.session``).
_OWN_CHECK = frozenset({"harfanglab"})


def _signature_platforms(body: Mapping[str, Any]) -> list[str]:
    configurations = body.get("configurations")
    if not isinstance(configurations, Mapping):
        return []
    found: list[str] = []
    for platform, block in configurations.items():
        if platform in _OWN_CHECK:
            continue
        yara_block = block.get("yara") if isinstance(block, Mapping) else None
        if isinstance(yara_block, Mapping) and "signature" in yara_block:
            found.append(str(platform))
    return found


def _first_paths(root: yaml.Node) -> dict[int, tuple[str, ...]]:
    """The path at which each node first appears, in document order."""
    first: dict[int, tuple[str, ...]] = {}
    stack: list[tuple[yaml.Node, tuple[str, ...]]] = [(root, ())]
    while stack:
        node, path = stack.pop()
        if id(node) in first:
            continue
        first[id(node)] = path
        children: list[tuple[yaml.Node, tuple[str, ...]]] = []
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                key = key_node.value if isinstance(key_node, yaml.ScalarNode) else "?"
                children.append((value_node, (*path, str(key))))
        elif isinstance(node, yaml.SequenceNode):
            children = [(child, (*path, str(i))) for i, child in enumerate(node.value)]
        stack.extend(reversed(children))
    return first


def _node_at(root: yaml.Node, path: tuple[str, ...]) -> yaml.Node | None:
    node: yaml.Node | None = root
    for key in path:
        if not isinstance(node, yaml.MappingNode):
            return None
        node = next(
            (v for k, v in node.value if isinstance(k, yaml.ScalarNode) and k.value == key),
            None,
        )
    return node


def aliased_signatures(text: str, platforms: list[str]) -> list[str]:
    """The platforms of *platforms* whose ``yara.signature`` is a YAML alias in *text*."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return []  # the loader reports it
    if root is None:
        return []
    first = _first_paths(root)
    aliased: list[str] = []
    for platform in platforms:
        path = ("configurations", platform, "yara", "signature")
        node = _node_at(root, path)
        if node is not None and first.get(id(node)) != path:
            aliased.append(platform)
    return aliased


def yara_signature_alias_issues(
    body: Mapping[str, Any],
    *,
    object_uuid: str,
    object_type: str,
    file_path: Path | None,
) -> list[ValidationIssue]:
    """``yara_signature_alias`` for each ``yara.signature`` that is a YAML alias."""
    if object_type != "rule" or file_path is None:
        return []
    platforms = _signature_platforms(body)
    if not platforms:
        return []
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return []
    return [
        ValidationIssue(
            code=CODE,
            severity="error",
            object_uuid=object_uuid,
            object_type=object_type,
            file_path=file_path,
            field_path=("configurations", platform, "yara", "signature"),
            message=(
                f"configurations.{platform}.yara.signature is a YAML alias; "
                "write the YARA signature out in the block"
            ),
            suggestion="Replace the alias (*name) with the signature text",
        )
        for platform in aliased_signatures(text, platforms)
    ]
