#!/usr/bin/env python3
"""Mechanical Phase 2 identifier renames across Python sources (no behaviour change)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules"}

REPLACEMENTS: list[tuple[str, str]] = [
    ("CarbonBlackCloudEngineInit", "CarbonBlackCloudConnection"),
    ("SplunkEngineInit", "SplunkConnection"),
    ("TenantDeploymentModel", "DeploymentBatch"),
    ("TideDefinitionsModels", "SharedModels"),
    ("PluginEnginesLoader", "PlatformLoader"),
    ("DetectionSystems", "DetectionPlatforms"),
    ("TideObjectMetadata", "ObjectMetadata"),
    ("TideObjectReferences", "ObjectReferences"),
    ("SystemConfigurationModel", "PlatformConfigurationBase"),
    ("remove_tide_keywords", "strip_framework_keywords"),
    ("TIDE_DEBUG_ENABLED", "DEBUG_ENABLED"),
    ("TIDE_INDEXES_PATH", "INDEX_PATH"),
    ("ValidateQuery", "QueryValidator"),
    ("DeployEngine", "PlatformEngine"),
    ("DeployMDR", "RuleDeployer"),
    ("PluginTide", "PlatformEngineBase"),
    ("SystemLoader", "PlatformConfigLoader"),
    ("TideErrors", "Errors"),
    ("TideRepo", "GitRepository"),
    ("TideConfigs", "ConfigurationModels"),
    ("TideLoader", "ObjectLoader"),
    ("HelperTide", "DebugHelpers"),
    ("IndexTide", "IndexManager"),
    ("coretide_intro", "print_banner"),
    ("TIDE_CONFIG", "CORE_CONFIG"),
    ("TIDE_MODELS", "OBJECT_TYPES"),
    ("TIDE_PATHS", "PATHS"),
    ("TideModels.MDR", "TideModels.DetectionRule"),
    ("load_mdr", "load_rule"),
    ("load_dom", "load_objective"),
    ("DataTide", "OpenTide"),
]

SHIM_FILES = {
    ROOT / "Engines/modules/tide.py",
    ROOT / "Engines/modules/models.py",
    ROOT / "Engines/modules/deployment.py",
    ROOT / "Engines/modules/plugins.py",
    ROOT / "Engines/modules/object_models.py",
    ROOT / "Engines/modules/errors.py",
    ROOT / "Engines/modules/enums.py",
    ROOT / "Engines/modules/environment.py",
    ROOT / "Engines/modules/index.py",
    ROOT / "Engines/modules/loaders/object_loader.py",
    ROOT / "Engines/modules/loaders/system_loader.py",
    ROOT / "Engines/modules/registry.py",
    ROOT / "Engines/modules/platforms.py",
    ROOT / "Engines/modules/logs.py",
    ROOT / "Engines/modules/git_repo.py",
    ROOT / "src/opentide/__init__.py",
}


def iter_py_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in {"apply_phase2_renames.py"}:
            continue
        files.append(path)
    return files


def apply_replacements(content: str, path: Path) -> str:
    if path in SHIM_FILES:
        return content
    for old, new in REPLACEMENTS:
        content = content.replace(old, new)
    return content


def main() -> int:
    changed = 0
    for path in iter_py_files():
        original = path.read_text(encoding="utf-8")
        updated = apply_replacements(original, path)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed += 1
            print(f"updated: {path.relative_to(ROOT)}")
    print(f"done — {changed} files changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
