"""Google SecOps checks that need more than the block (google-secops-1.0, yara-l-1.0).

- ``google_secops_name_duplicate``: two enabled ``google_secops`` blocks resolve
  to one YARA-L rule name, compared case-insensitively. A composite rule that
  names one would match both, and Google's own ``content_manager`` treats
  names as case-insensitively unique.
- ``yaral_section_alias``: a section key is a YAML alias instead of its own
  text. The loaded body cannot tell an alias from text written in place, so the
  file's node graph is read.
- The advisories, as ``validate`` warnings.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from opentide.validation.issues import ValidationIssue

NAME_DUPLICATE = "google_secops_name_duplicate"
SECTION_ALIAS = "yaral_section_alias"
_BLOCK = ("configurations", "google_secops")


def _rule_name(body: Mapping[str, Any]) -> str | None:
    from opentide.platforms.google_secops.compile import rule_name

    configurations = body.get("configurations")
    block = configurations.get("google_secops") if isinstance(configurations, Mapping) else None
    if not isinstance(block, Mapping) or block.get("enabled") is not True:
        return None
    title = body.get("name")
    block_name = block.get("name")
    metadata = body.get("metadata")
    uuid = metadata.get("uuid") if isinstance(metadata, Mapping) else None
    if not isinstance(title, str) or not (block_name is None or isinstance(block_name, str)):
        return None
    return rule_name(title, block_name or None, str(uuid or "")) or None


def google_secops_name_issues(
    rules: Mapping[str, Mapping[str, Any]],
    in_scope: Iterable[str],
    file_of: Callable[[str], Path | None],
) -> list[ValidationIssue]:
    """``google_secops_name_duplicate`` for each rule in *in_scope* sharing its rule name."""
    names: dict[str, str] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    for uuid, body in rules.items():
        if isinstance(body, Mapping) and (name := _rule_name(body)) is not None:
            names[str(uuid)] = name
            by_name[name.lower()].append(str(uuid))
    issues: list[ValidationIssue] = []
    for uuid in in_scope:
        name = names.get(uuid)
        others = [other for other in by_name.get((name or "").lower(), []) if other != uuid]
        if name is None or not others:
            continue
        issues.append(
            ValidationIssue(
                code=NAME_DUPLICATE,
                severity="error",
                object_uuid=uuid,
                object_type="rule",
                file_path=file_of(uuid),
                field_path=_BLOCK,
                message=(
                    f"Google SecOps rule name {name!r} is also the rule name of rule(s) "
                    f"{', '.join(sorted(others))} (compared case-insensitively); a composite "
                    "rule matching it by detection.detection.rule_name would match both"
                ),
                suggestion="Set a distinct configurations.google_secops.name on one of the rules",
                context={"value": name},
            )
        )
    return issues


def _node_paths(root: yaml.Node) -> dict[int, tuple[str, ...]]:
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


def aliased_sections(text: str) -> list[str]:
    """The section keys of the ``google_secops`` block that are YAML aliases in *text*."""
    from opentide.platforms.google_secops.yaral import SECTION_KEYS

    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError):
        return []  # the loader reports it
    if not isinstance(root, yaml.MappingNode):
        return []
    block: yaml.Node | None = root
    for key in _BLOCK:
        if not isinstance(block, yaml.MappingNode):
            return []
        block = next(
            (v for k, v in block.value if isinstance(k, yaml.ScalarNode) and k.value == key),
            None,
        )
    if not isinstance(block, yaml.MappingNode):
        return []
    first = _node_paths(root)
    aliased: list[str] = []
    for key_node, value_node in block.value:
        key = key_node.value if isinstance(key_node, yaml.ScalarNode) else None
        if key in SECTION_KEYS and first.get(id(value_node)) != (*_BLOCK, key):
            aliased.append(str(key))
    return aliased


def section_alias_issues(
    body: Mapping[str, Any],
    *,
    object_uuid: str,
    object_type: str,
    file_path: Path | None,
) -> list[ValidationIssue]:
    """``yaral_section_alias`` for each section key of the block that is a YAML alias."""
    configurations = body.get("configurations")
    block = configurations.get("google_secops") if isinstance(configurations, Mapping) else None
    if object_type != "rule" or file_path is None or not isinstance(block, Mapping):
        return []
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return []  # the loader reports an unreadable file
    if "*" not in text:
        return []
    return [
        ValidationIssue(
            code=SECTION_ALIAS,
            severity="error",
            object_uuid=object_uuid,
            object_type=object_type,
            file_path=file_path,
            field_path=(*_BLOCK, key),
            message=(
                f"configurations.google_secops.{key} is a YAML alias; a YARA-L section is "
                "written in the block, so what the rule deploys is readable there"
            ),
            suggestion=f"Write the {key} text under configurations.google_secops.{key}",
        )
        for key in aliased_sections(text)
    ]


def google_secops_advisory_issues(
    body: Mapping[str, Any],
    *,
    object_uuid: str,
    object_type: str,
    file_path: Path | None,
) -> list[ValidationIssue]:
    """One warning per advisory of the rule's ``google_secops`` block."""
    if object_type != "rule":
        return []
    from opentide.platforms.google_secops.advisories import google_secops_advisories

    return [
        ValidationIssue(
            code=advisory.code,
            severity="warning",
            object_uuid=object_uuid,
            object_type=object_type,
            file_path=file_path,
            field_path=advisory.field_path,
            message=advisory.message,
        )
        for advisory in google_secops_advisories(body)
    ]
