"""Exabeam rule names across the workspace (exabeam-1.0, Constraints).

``exabeam_name_duplicate``: two enabled ``exabeam`` blocks that resolve to the
same Exabeam rule name, compared case-insensitively. Exabeam's import refuses
a rule whose name exists, Search links rules by name, and deploy's name check
would refuse the second create (``exabeam_name_conflict``).

``exabeam_name_length``: a rule whose block sets no ``name`` and whose
opentide ``name`` is longer than 128 characters. The block's own ``name`` is
checked by the block model; the rule name is not the block's to see.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from opentide.validation.issues import ValidationIssue

CODE = "exabeam_name_duplicate"
LENGTH_CODE = "exabeam_name_length"

_PATH = ("configurations", "exabeam", "name")


def _block(body: Mapping[str, Any]) -> Mapping[str, Any] | None:
    configurations = body.get("configurations")
    block = configurations.get("exabeam") if isinstance(configurations, Mapping) else None
    return block if isinstance(block, Mapping) else None


def _exabeam_name(body: Mapping[str, Any], *, enabled_only: bool = True) -> str | None:
    block = _block(body)
    if block is None or (enabled_only and block.get("enabled") is not True):
        return None
    rule_name = body.get("name")
    block_name = block.get("name")
    if block_name and isinstance(block_name, str):
        return block_name
    return rule_name if isinstance(rule_name, str) and rule_name else None


def exabeam_name_issues(
    rules: Mapping[str, Mapping[str, Any]],
    in_scope: Iterable[str],
    file_of: Callable[[str], Path | None],
) -> list[ValidationIssue]:
    """``exabeam_name_duplicate`` and ``exabeam_name_length`` for each rule in *in_scope*."""
    from opentide.platforms.exabeam.constraints import NAME_LIMIT

    by_name: dict[str, list[str]] = defaultdict(list)
    for uuid, body in rules.items():
        if isinstance(body, Mapping) and (name := _exabeam_name(body)) is not None:
            by_name[name.casefold()].append(str(uuid))
    issues: list[ValidationIssue] = []
    for uuid in in_scope:
        body = rules.get(uuid)
        if not isinstance(body, Mapping):
            continue
        block = _block(body)
        resolved = _exabeam_name(body, enabled_only=False)
        if (
            block is not None
            and not block.get("name")
            and resolved is not None
            and len(resolved) > NAME_LIMIT
        ):
            issues.append(
                ValidationIssue(
                    code=LENGTH_CODE,
                    severity="error",
                    object_uuid=uuid,
                    object_type="rule",
                    file_path=file_of(uuid),
                    field_path=_PATH,
                    message=(
                        f"the Exabeam rule name (the rule name) is {len(resolved)} characters, "
                        f"more than {NAME_LIMIT}"
                    ),
                    suggestion="Set a shorter configurations.exabeam.name",
                )
            )
        name = _exabeam_name(body)
        others = [other for other in by_name.get((name or "").casefold(), []) if other != uuid]
        if name is None or not others:
            continue
        issues.append(
            ValidationIssue(
                code=CODE,
                severity="error",
                object_uuid=uuid,
                object_type="rule",
                file_path=file_of(uuid),
                field_path=_PATH,
                message=(
                    f"Exabeam rule name {name!r} is also the name of rule(s) "
                    f"{', '.join(sorted(others))}, compared case-insensitively; Exabeam rule "
                    "names are unique"
                ),
                suggestion="Set a distinct configurations.exabeam.name on one of the rules",
                context={"value": name},
            )
        )
    return issues
