"""Vendor rule ids on rules and their deployment state shards (RFC 0010).

``rule_id``, ``rule_id_bundle`` and ``rule_id::<tenant>`` are no longer keys
of any platform block: the id lives in ``.opentide/states/deployment/``. A
rule that still carries one fails ``external_id_in_rule``. A shard that exists
is checked for shape; a missing shard is not an error. Full-workspace
validation checks every shard file, including shards whose rule is gone
(:func:`deployment_state_issues`); a narrow run checks the selected rules'.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from opentide.states.deployment import (
    DeploymentState,
    DeploymentStateError,
    is_legacy_external_id_key,
    legacy_external_id_keys,
    scan_deployment_states,
    shard_path,
)
from opentide.validation.issues import ValidationIssue

MIGRATE_SUGGESTION = (
    "Run 'opentide deploy migrate-state' and commit the rule together with "
    ".opentide/states/deployment/"
)


def is_superseded_extra_key(issue: ValidationIssue) -> bool:
    """A schema error for a legacy id key, which ``external_id_in_rule`` reports instead."""
    path = issue.field_path
    return (
        issue.code == "schema_validation"
        and len(path) == 3
        and path[0] == "configurations"
        and is_legacy_external_id_key(path[2])
    )


def external_id_issues(
    body: Mapping[str, Any],
    *,
    object_uuid: str,
    object_type: str,
    file_path: Path | None = None,
    workspace: Path | None = None,
    check_shard: bool = True,
) -> list[ValidationIssue]:
    """``external_id_in_rule`` for legacy keys, ``deployment_state_*`` for a broken shard.

    *check_shard* is off when :func:`deployment_state_issues` already checks
    the whole directory, so a broken shard is reported once.
    """
    if object_type != "rule":
        return []
    issues = [
        ValidationIssue(
            code="external_id_in_rule",
            severity="error",
            object_uuid=object_uuid,
            object_type=object_type,
            file_path=file_path,
            field_path=("configurations", platform, key),
            message=(
                f"Vendor rule id key {key!r} is not allowed on the {platform} block; "
                "external ids live in .opentide/states/deployment/<uuid>.json"
            ),
            suggestion=MIGRATE_SUGGESTION,
        )
        for platform, key in legacy_external_id_keys(body)
    ]
    if not check_shard:
        return issues
    try:
        path = shard_path(object_uuid, workspace)
        DeploymentState.load(object_uuid, workspace)
    except DeploymentStateError as error:
        if error.code == "deployment_state_shape" and "path" not in error.context:
            # metadata.uuid is not a UUID: invalid_uuid already says so.
            return issues
        issues.append(
            ValidationIssue(
                code=error.code,
                severity="error",
                object_uuid=object_uuid,
                object_type=object_type,
                file_path=file_path,
                message=error.message,
                context={"shard": str(error.context.get("path", path))},
            )
        )
    return issues


def deployment_state_issues(workspace: Path | None = None) -> list[ValidationIssue]:
    """Every unusable file under ``.opentide/states/deployment/``, orphans included."""
    return [
        ValidationIssue(
            code=error.code,
            severity="error",
            file_path=Path(str(error.context["path"])) if "path" in error.context else None,
            message=error.message,
            context={"shard": str(error.context.get("path", ""))},
        )
        for error in scan_deployment_states(workspace)
    ]
