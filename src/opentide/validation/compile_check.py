"""Compile each rule a deploy would send, so a rule that validates deploys (#660).

The platform compilers own their requirements: Sentinel needs ``grouping.alert``
and, unless ``scheduling.nrt``, ``scheduling.frequency``; none of that is in the
platform schema. Rather than restate it, ``validate`` runs the same offline
compiler ``deploy --dry-run`` runs and reports its error with the same code,
message and help, framed at the key at fault (or the nearest key the file has).
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from pathlib import Path
from typing import Any

from opentide.models.deployment_enums import StatusStrategy
from opentide.validation.issues import ValidationIssue

#: Strategies whose rules a deploy compiles; an inert rule is never sent and a
#: deleted one is removed by its vendor id.
_COMPILED_STRATEGIES = frozenset(
    {
        StatusStrategy.PREVIEW,
        StatusStrategy.RELEASE,
        StatusStrategy.UNIVERSAL,
        StatusStrategy.DISABLEMENT,
    }
)

_DISPLAY_NAMES = {"sentinel": "Sentinel", "elastic": "Elastic"}


def compile_issues(
    rule: Any,
    body: Mapping[str, Any],
    enabled: Set[str],
    *,
    object_uuid: str = "",
    file_path: Path | None = None,
) -> list[ValidationIssue]:
    """One error per enabled platform with an offline compiler that cannot compile *rule*.

    *rule* is the loaded ``DetectionRule``; *body* the YAML it came from.
    """
    from opentide.deployment.preview import OFFLINE_COMPILERS, compile_diagnostic, compile_offline

    configurations = body.get("configurations")
    if not isinstance(configurations, Mapping):
        return []
    issues: list[ValidationIssue] = []
    for platform in sorted(OFFLINE_COMPILERS & set(enabled)):
        block = configurations.get(platform)
        if not isinstance(block, Mapping) or not _deploys(block.get("status")):
            continue
        try:
            compile_offline(platform, rule)
        except Exception as exc:
            name = _DISPLAY_NAMES.get(platform, platform)
            code, message, hint = compile_diagnostic(exc, name)
            field = getattr(exc, "field", None)
            field_path = tuple(field) if field else ("configurations", platform)
            issues.append(
                ValidationIssue(
                    code=code,
                    severity="error",
                    object_uuid=object_uuid,
                    object_type="rule",
                    file_path=file_path,
                    yaml_line=_nearest_line(file_path, field_path),
                    field_path=field_path,
                    message=message,
                    suggestion=hint,
                    context={"platform": platform},
                )
            )
    return issues


def _deploys(status: object) -> bool:
    """Whether a deploy compiles a rule in *status*; an unknown status is the schema's finding."""
    from opentide.deployment.utils import check_status

    if not isinstance(status, str):
        return False
    try:
        return check_status(status) in _COMPILED_STRATEGIES
    except (ValueError, TypeError):
        return False


def _nearest_line(file_path: Path | None, field_path: tuple[str, ...]) -> int | None:
    """0-based line of the deepest key of *field_path* the file has (the key at
    fault, or the block that should hold it)."""
    if file_path is None:
        return None
    from opentide.validation.errors import load_yaml_with_lines

    node = load_yaml_with_lines(file_path)
    line: int | None = None
    for key in field_path:
        marker = getattr(node, "lc", None)
        if not isinstance(node, Mapping) or key not in node or marker is None:
            break
        line = marker.key(key)[0]
        node = node[key]
    return line
