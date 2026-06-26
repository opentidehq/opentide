"""Inflight preview shards — per-object JSON overlays for open PR previews."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from opentide.core.io import load_yaml
from opentide.core.logging import get_logger
from opentide.registry.discovery import discover_workspace
from opentide.registry.paths import resolve_workspace_paths

logger = get_logger(__name__)

_OBJECT_YAML = re.compile(r"^objects/(threats|objectives|rules)/[^/]+\.(ya?ml)$")


def _object_version(body: dict[str, Any]) -> int:
    raw = (body.get("metadata") or {}).get("version")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _object_uuid(body: dict[str, Any]) -> str | None:
    raw = body.get("uuid") or (body.get("metadata") or {}).get("uuid")
    return str(raw) if raw else None


def _object_family(body: dict[str, Any]) -> str | None:
    schema = (body.get("metadata") or {}).get("schema")
    if isinstance(schema, str) and "::" in schema:
        return schema.split("::")[0]
    if body.get("threat"):
        return "threat"
    if body.get("objective"):
        return "objective"
    if body.get("configurations"):
        return "rule"
    return None


def _is_object_yaml(path: str) -> bool:
    normalised = path.replace("\\", "/")
    return bool(_OBJECT_YAML.match(normalised))


def _paths_from_env() -> list[Path]:
    raw = os.getenv("INFLIGHT_PATHS", "").strip()
    if not raw:
        return []
    return [Path(p) for p in raw.split(",") if p.strip()]


def _local_git_changed_paths() -> list[Path]:
    root = discover_workspace()
    for ref in ("origin/main", "main"):
        result = subprocess.run(
            ["git", "rev-parse", "--verify", ref],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        diff = subprocess.run(
            ["git", "diff", "--name-only", f"{ref}...HEAD", "--", "objects/"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if diff.returncode != 0:
            continue
        paths = [root / line for line in diff.stdout.splitlines() if line.strip()]
        return [p for p in paths if p.is_file()]
    return []


def changed_object_yaml_paths(
    plan: Any = None,
) -> list[Path]:
    """Return object YAML paths changed in the current CI or git context."""
    from opentide.deployment.ci import CIEnvironment
    from opentide.deployment.git_repo import diff_calculation
    from opentide.models.deployment_enums import DeploymentStrategy as Plan

    if plan is None:
        plan = Plan.STAGING
    explicit = _paths_from_env()
    if explicit:
        return explicit

    env = CIEnvironment().environment
    if env is CIEnvironment.CIPlatforms.LocalDebug:
        local = _local_git_changed_paths()
        if local:
            return local
        logger.warning("inflight_no_local_git_diff_found")
        return []

    scope = diff_calculation(plan)
    root = discover_workspace()
    return [root / p for p in scope if _is_object_yaml(p)]


def write_inflight_shards(
    paths: list[Path] | None = None,
    *,
    inflight_dir: Path | None = None,
    plan: Any = None,
) -> dict[str, Any]:
    """Write ``<uuid>.json`` preview shards for changed object YAML files."""
    resolved_paths = resolve_workspace_paths()
    target_dir = inflight_dir or resolved_paths["inflight"]
    target_dir.mkdir(parents=True, exist_ok=True)

    yaml_paths = paths if paths is not None else changed_object_yaml_paths(plan)
    written: list[str] = []

    for yaml_path in yaml_paths:
        body = load_yaml(yaml_path)
        if not isinstance(body, dict):
            logger.warning("inflight_skip_non_mapping", path=str(yaml_path))
            continue
        uuid = _object_uuid(body)
        if not uuid:
            logger.warning("inflight_skip_missing_uuid", path=str(yaml_path))
            continue
        shard_path = target_dir / f"{uuid}.json"
        shard_path.write_text(
            json.dumps(body, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        written.append(uuid)
        logger.info("inflight_shard_written", uuid=uuid, path=str(shard_path))

    return {"written": written, "count": len(written), "directory": str(target_dir)}


def load_inflight_shards(inflight_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load all inflight shards keyed by object UUID."""
    resolved_paths = resolve_workspace_paths()
    directory = inflight_dir or resolved_paths["inflight"]
    if not directory.is_dir():
        return {}

    shards: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("inflight_shard_invalid_json", path=str(path), error=str(exc))
            continue
        if not isinstance(body, dict):
            continue
        uuid = _object_uuid(body)
        if uuid:
            shards[uuid] = body
    return shards


def _ingest_signals(
    objects_index: dict[str, Any], objective_uuid: str, body: dict[str, Any]
) -> None:
    objective = body.get("objective")
    if not isinstance(objective, dict):
        return
    signals = objective.get("signals") or []
    if not isinstance(signals, list):
        return
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        signal_uuid = signal.get("uuid")
        if not signal_uuid:
            continue
        signal_copy = signal.copy()
        signal_copy["parent"] = objective_uuid
        objects_index.setdefault("signal", {})[str(signal_uuid)] = signal_copy


def apply_inflight_overlay(
    objects_index: dict[str, Any],
    shards: dict[str, dict[str, Any]] | None = None,
    *,
    inflight_dir: Path | None = None,
) -> dict[str, int]:
    """Merge inflight shards into the registry objects index (version-gated)."""
    overlay = shards if shards is not None else load_inflight_shards(inflight_dir)
    added = 0
    updated = 0

    for uuid, body in overlay.items():
        family = _object_family(body)
        if not family or family not in objects_index:
            logger.warning("inflight_skip_unknown_family", uuid=uuid, family=family)
            continue

        bucket = objects_index[family]
        existing = bucket.get(uuid)
        if existing is None:
            bucket[uuid] = body
            added += 1
        elif _object_version(body) >= _object_version(existing):
            bucket[uuid] = body
            updated += 1
        else:
            continue

        if family == "objective":
            _ingest_signals(objects_index, uuid, body)

    if added or updated:
        logger.info("inflight_overlay_applied", added=added, updated=updated)
    return {"added": added, "updated": updated}


def run(inflight_dir: Path | None = None) -> dict[str, Any]:
    """CLI entry: write inflight shards for the current change set."""
    from opentide.core.registry import OpenTide
    from opentide.models.deployment_enums import DeploymentStrategy

    OpenTide.initialise()
    plan_name = os.getenv("DEPLOYMENT_PLAN", DeploymentStrategy.STAGING.name)
    try:
        plan = DeploymentStrategy[plan_name]
    except KeyError:
        plan = DeploymentStrategy.STAGING
    return write_inflight_shards(inflight_dir=inflight_dir, plan=plan)
