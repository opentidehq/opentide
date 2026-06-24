"""Generation artifact checksum gate for byte-equivalent CI verification."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

from opentide.core.files import resolve_configurations
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.schema_registry import identifiers_for_families
from opentide.models.version import SchemaVersion
from opentide.registry.artifacts import schema_artifact_name
from opentide.registry.discovery import OPENTIDE_DIR
from opentide.registry.paths import resolve_workspace_paths

TIDE_PREFIX = "tide:"
REPO_PREFIX = "repo:"
TIDE_WORKSPACE_DIR = "tests/fixtures/generation/tide_workspace"


def tide_instance_root(repo_root: Path) -> Path:
    """Return portable tide instance root (workspace in tests, parent in production)."""
    workspace_env = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    if workspace_env:
        return Path(workspace_env).resolve()
    workspace = repo_root / TIDE_WORKSPACE_DIR
    if workspace.is_dir():
        return workspace.resolve()
    return repo_root.parent


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _workspace_config() -> dict[str, Any]:
    configs = resolve_configurations()
    return configs.get("paths") or configs["global"]


def generation_artifact_specs(repo_root: Path) -> list[tuple[str, Path]]:
    """Return portable artifact keys and absolute paths."""
    cfg = _workspace_config()
    paths = resolve_workspace_paths()
    artifacts = cfg.get("artifacts", {})
    schema_map: dict[str, str] = dict(artifacts.get("schemas", cfg.get("json_schemas", {})))
    template_map: dict[str, str] = dict(artifacts.get("templates", cfg.get("templates", {})))

    schema_dir = Path(paths["json_schemas"])
    template_dir = Path(paths["templates"])
    specs: list[tuple[str, Path]] = []

    for schema_id in identifiers_for_families(CORE_OBJECT_TYPES):
        family = SchemaVersion.parse(schema_id).family
        filename = schema_map.get(family) or schema_artifact_name(schema_id)
        rel = f"{OPENTIDE_DIR}/schemas/{filename}"
        specs.append((f"{TIDE_PREFIX}{rel}", schema_dir / filename))
        template_name = template_map.get(family)
        if template_name:
            rel_t = f"{OPENTIDE_DIR}/templates/{template_name}"
            specs.append((f"{TIDE_PREFIX}{rel_t}", template_dir / template_name))

    visibility_name = schema_map.get("visibility")
    if visibility_name:
        rel = f"{OPENTIDE_DIR}/schemas/{visibility_name}"
        specs.append((f"{TIDE_PREFIX}{rel}", schema_dir / visibility_name))

    router_name = schema_map.get("router")
    if router_name:
        rel = f"{OPENTIDE_DIR}/schemas/{router_name}"
        specs.append((f"{TIDE_PREFIX}{rel}", schema_dir / router_name))

    subschema_templates = (
        Path(paths.get("platform_templates", paths.get("subschemas", ".")))
        / "MDR Systems Deployment"
        / "Templates"
    )
    if subschema_templates.is_dir():
        for path in sorted(subschema_templates.glob("*.yaml")):
            rel_path = path.relative_to(repo_root.resolve())
            specs.append((f"{REPO_PREFIX}{rel_path.as_posix()}", path))

    return specs


def collect_generation_checksums(repo_root: Path) -> dict[str, str]:
    """Collect sha256 checksums keyed by portable tide:/repo: paths."""
    checksums: dict[str, str] = {}
    for key, path in generation_artifact_specs(repo_root):
        if path.is_file():
            checksums[key] = _sha256(path)
    return checksums


def resolve_artifact_path(key: str, *, repo_root: Path) -> Path:
    if key.startswith(REPO_PREFIX):
        return (repo_root / key.removeprefix(REPO_PREFIX)).resolve()
    if key.startswith(TIDE_PREFIX):
        return (tide_instance_root(repo_root) / key.removeprefix(TIDE_PREFIX)).resolve()
    raise KeyError(f"Unknown artifact key prefix: {key}")


def load_checksum_baseline(baseline_path: Path) -> dict[str, str]:
    return cast(dict[str, str], json.loads(baseline_path.read_text(encoding="utf-8")))


def write_checksum_baseline(checksums: dict[str, str], baseline_path: Path) -> None:
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(checksums, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def verify_generation_checksums(
    expected: dict[str, str],
    *,
    repo_root: Path,
) -> dict[str, str]:
    """Compare current generation artifact checksums against a baseline."""
    actual = collect_generation_checksums(repo_root)
    missing = {k: v for k, v in expected.items() if k not in actual}
    extra = {k: v for k, v in actual.items() if k not in expected}
    changed = {
        k: {"expected": expected[k], "actual": actual[k]}
        for k in expected
        if k in actual and actual[k] != expected[k]
    }
    if missing or extra or changed:
        detail = {"missing": missing, "extra": extra, "changed": changed}
        raise AssertionError(f"Generation artifact checksum mismatch: {detail}")
    return actual
