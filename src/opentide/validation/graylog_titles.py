"""``graylog_title_duplicate``: one event definition title per enabled block (graylog-1.0).

Graylog allows two definitions with one title, and its alert list cannot tell
them apart. The check reads every rule of the workspace and warns on each rule
in scope whose enabled ``graylog`` block resolves to a title another one does.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from opentide.validation.issues import ValidationIssue


def _title(body: Mapping[str, Any]) -> str | None:
    configurations = body.get("configurations")
    block = configurations.get("graylog") if isinstance(configurations, Mapping) else None
    if not isinstance(block, Mapping) or block.get("enabled") is not True:
        return None
    rule_name = body.get("name")
    block_name = block.get("name")
    if isinstance(block_name, str) and block_name:
        return block_name
    return rule_name if isinstance(rule_name, str) and rule_name else None


def graylog_title_issues(
    rules: Mapping[str, Mapping[str, Any]],
    in_scope: Iterable[str],
    file_of: Callable[[str], Path | None],
) -> list[ValidationIssue]:
    """``graylog_title_duplicate`` for each rule in *in_scope* sharing its definition title."""
    by_title: dict[str, list[str]] = defaultdict(list)
    for uuid, body in rules.items():
        if isinstance(body, Mapping) and (title := _title(body)) is not None:
            by_title[title].append(str(uuid))
    issues: list[ValidationIssue] = []
    for uuid in in_scope:
        body = rules.get(uuid)
        title = _title(body) if isinstance(body, Mapping) else None
        others = [other for other in by_title.get(title or "", []) if other != uuid]
        if title is None or not others:
            continue
        issues.append(
            ValidationIssue(
                code="graylog_title_duplicate",
                severity="warning",
                object_uuid=uuid,
                object_type="rule",
                file_path=file_of(uuid),
                field_path=("configurations", "graylog"),
                message=(
                    f"Graylog event definition title {title!r} is also the title of rule(s) "
                    f"{', '.join(sorted(others))}; Graylog's alert list cannot tell them apart"
                ),
                suggestion="Set a distinct configurations.graylog.name on one of the rules",
                context={"value": title},
            )
        )
    return issues
