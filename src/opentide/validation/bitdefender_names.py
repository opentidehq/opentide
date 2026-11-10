"""``bitdefender_name_duplicate``: one GravityZone name per enabled block (bitdefender-1.0).

GravityZone refuses a second rule with one name in a company, so two enabled
``bitdefender`` blocks that resolve to the same GravityZone name would fail
the second create at deploy. The check reads every rule of the workspace and
reports each rule in scope whose name another rule shares.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from opentide.validation.issues import ValidationIssue

CODE = "bitdefender_name_duplicate"


def _gravityzone_name(body: Mapping[str, Any]) -> str | None:
    from opentide.platforms.bitdefender.compile import gravityzone_name

    configurations = body.get("configurations")
    block = configurations.get("bitdefender") if isinstance(configurations, Mapping) else None
    if not isinstance(block, Mapping) or block.get("enabled") is not True:
        return None
    rule_name = body.get("name")
    block_name = block.get("name")
    if not isinstance(rule_name, str) or not (block_name is None or isinstance(block_name, str)):
        return None
    return gravityzone_name(rule_name, block_name) or None


def bitdefender_name_issues(
    rules: Mapping[str, Mapping[str, Any]],
    in_scope: Iterable[str],
    file_of: Callable[[str], Path | None],
) -> list[ValidationIssue]:
    """``bitdefender_name_duplicate`` for each rule in *in_scope* sharing its GravityZone name."""
    by_name: dict[str, list[str]] = defaultdict(list)
    for uuid, body in rules.items():
        if isinstance(body, Mapping) and (name := _gravityzone_name(body)) is not None:
            by_name[name].append(str(uuid))
    issues: list[ValidationIssue] = []
    for uuid in in_scope:
        body = rules.get(uuid)
        name = _gravityzone_name(body) if isinstance(body, Mapping) else None
        others = [other for other in by_name.get(name or "", []) if other != uuid]
        if name is None or not others:
            continue
        issues.append(
            ValidationIssue(
                code=CODE,
                severity="error",
                object_uuid=uuid,
                object_type="rule",
                file_path=file_of(uuid),
                field_path=("configurations", "bitdefender", "name"),
                message=(
                    f"GravityZone name {name!r} is also the name of rule(s) "
                    f"{', '.join(sorted(others))}; GravityZone refuses a second rule with one "
                    "name in a company"
                ),
                suggestion="Set a distinct configurations.bitdefender.name on one of the rules",
                context={"value": name},
            )
        )
    return issues
