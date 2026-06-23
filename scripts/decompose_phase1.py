#!/usr/bin/env python3
"""Phase 1: decompose tide.py, models.py, deployment.py monoliths into focused modules."""

from __future__ import annotations

import shutil
from pathlib import Path

MODULES = Path(__file__).resolve().parent.parent / "Engines" / "modules"


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def write_module(path: Path, header: str, body: str, extra_imports: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parts = [header.rstrip()]
    if extra_imports:
        parts.append(extra_imports.rstrip())
    parts.append(body.lstrip())
    content = "\n\n".join(parts)
    if not content.endswith("\n"):
        content += "\n"
    path.write_text(content, encoding="utf-8")


def slice_lines(lines: list[str], start: int, end: int | None = None) -> str:
    """1-based inclusive start, optional 1-based inclusive end."""
    if end is None:
        return "".join(lines[start - 1 :])
    return "".join(lines[start - 1 : end])


def decompose_tide() -> None:
    src = MODULES / "tide.py"
    lines = read_lines(src)
    header = slice_lines(lines, 1, 38)

    write_module(MODULES / "environment.py", header, slice_lines(lines, 42, 131))
    write_module(MODULES / "index.py", header, slice_lines(lines, 133, 317))
    write_module(MODULES / "loaders/system_loader.py", header, slice_lines(lines, 320, 732))
    write_module(MODULES / "loaders/config_loader.py", header, slice_lines(lines, 733, 832))
    write_module(
        MODULES / "loaders/object_loader.py",
        header,
        slice_lines(lines, 833, 1189),
        "\n".join(
            [
                "from opentide.loading.platform_loader import PlatformConfigLoader",
                "from opentide.core.environment import DebugHelpers",
            ]
        ),
    )
    write_module(
        MODULES / "registry.py",
        header,
        slice_lines(lines, 1190, None),
        "\n".join(
            [
                "from opentide.core.environment import DebugHelpers",
                "from opentide.core.index_legacy import IndexManager",
                "from opentide.loading.config_loader import ConfigurationsLoader",
                "from opentide.loading.compat import ObjectLoader",
            ]
        ),
    )
    (MODULES / "loaders/__init__.py").write_text("", encoding="utf-8")

    (MODULES / "tide.py").write_text(
        '''\
"""Backward-compatibility re-export shim for tide module."""

from opentide.models.legacy import DetectionPlatforms
from opentide.core.registry import OpenTide
from opentide.core.index_legacy import IndexManager
from opentide.core.environment import DebugHelpers
from opentide.loading.compat import ObjectLoader

__all__ = [
    "OpenTide",
    "IndexManager",
    "DebugHelpers",
    "ObjectLoader",
    "DetectionPlatforms",
]
''',
        encoding="utf-8",
    )


def decompose_models() -> None:
    src = MODULES / "models.py"
    lines = read_lines(src)
    header = slice_lines(lines, 1, 21)

    write_module(MODULES / "enums.py", header, slice_lines(lines, 23, 78))
    write_module(
        MODULES / "system_models.py",
        header,
        slice_lines(lines, 80, 130) + slice_lines(lines, 624, 662),
        "\n".join(
            [
                "from opentide.models.deployment_enums import DeploymentStrategy",
                "from opentide.models.object_models import TideModels",
            ]
        ),
    )
    write_module(
        MODULES / "config_models.py",
        header,
        slice_lines(lines, 131, 250),
        "\n".join(
            [
                "from opentide.models.deployment_enums import StatusStrategy",
                "from opentide.models.system_models import SystemConfig",
            ]
        ),
    )
    write_module(MODULES / "object_models.py", header, slice_lines(lines, 251, 622))

    (MODULES / "models.py").write_text(
        '''\
"""Backward-compatibility re-export shim for models module."""

from opentide.models.deployment_enums import StatusStrategy, DetectionPlatforms, DeploymentStrategy
from opentide.models.system_models import SystemConfig, DeploymentBatch, TenantDeployment
from opentide.models.config_models import ConfigurationModels
from opentide.models.object_models import SharedModels, TideModels

__all__ = [
    "StatusStrategy",
    "DetectionPlatforms",
    "DeploymentStrategy",
    "SystemConfig",
    "ConfigurationModels",
    "SharedModels",
    "TideModels",
    "DeploymentBatch",
    "TenantDeployment",
]
''',
        encoding="utf-8",
    )


def decompose_deployment() -> None:
    src = MODULES / "deployment.py"
    lines = read_lines(src)
    header = slice_lines(lines, 1, 34)

    write_module(MODULES / "ci.py", header, slice_lines(lines, 81, 119))
    write_module(
        MODULES / "git_repo.py",
        header,
        slice_lines(lines, 36, 79) + slice_lines(lines, 263, 501),
        "from opentide.deployment.ci import CIEnvironment",
    )

    utils_extra = "\n".join(
        [
            "from opentide.core.registry import OpenTide, DebugHelpers",
            "from opentide.models.legacy import StatusStrategy, DeploymentStrategy",
            "from opentide.deployment.ci import CIEnvironment",
            "from opentide.deployment.git_repo import (",
            "    GitRepository,",
            "    modified_mdr_files,",
            "    diff_calculation,",
            ")",
            "",
            "SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index",
            "DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)",
        ]
    )
    write_module(
        MODULES / "deployment_utils.py",
        header,
        slice_lines(lines, 124, 623),
        utils_extra,
    )
    write_module(
        MODULES / "deployment_planning.py",
        header,
        slice_lines(lines, 625, None),
        "\n".join(
            [
                "from opentide.core.registry import OpenTide, ObjectLoader",
                "from opentide.models.legacy import (",
                "    SharedModels,",
                "    TideModels,",
                "    SystemConfig,",
                "    DeploymentStrategy,",
                "    TenantDeployment,",
                "    DeploymentBatch,",
                "    DetectionPlatforms,",
                ")",
                "from opentide.generation.framework import unroll_dot_dict",
            ]
        ),
    )

    (MODULES / "deployment.py").write_text(
        '''\
"""Backward-compatibility re-export shim for deployment module."""

from opentide.deployment.ci import CIEnvironment
from opentide.deployment.git_repo import GitRepository, modified_mdr_files, diff_calculation
from opentide.deployment.utils import (
    SYSTEMS_CONFIGS_INDEX,
    DEPRECATED_STATUSES,
    check_status,
    make_deploy_plan,
    enabled_systems,
    Proxy,
    ExternalIdHelper,
)
from opentide.deployment.planning import TideDeployment

__all__ = [
    "CIEnvironment",
    "GitRepository",
    "modified_mdr_files",
    "diff_calculation",
    "SYSTEMS_CONFIGS_INDEX",
    "DEPRECATED_STATUSES",
    "check_status",
    "make_deploy_plan",
    "enabled_systems",
    "Proxy",
    "ExternalIdHelper",
    "TideDeployment",
]
''',
        encoding="utf-8",
    )


def relocate_system_mixins() -> None:
    systems_dir = MODULES / "systems"
    for stem in ("carbon_black_cloud", "splunk"):
        src = MODULES / f"{stem}.py"
        dst = systems_dir / f"{stem}.py"
        shutil.copy2(src, dst)
        src.write_text(
            f'''\
"""Backward-compatibility re-export shim."""

from opentide.core.systems.{stem} import *  # noqa: F403
''',
            encoding="utf-8",
        )


def main() -> None:
    decompose_tide()
    decompose_models()
    decompose_deployment()
    relocate_system_mixins()
    print("Phase 1 decomposition complete.")


if __name__ == "__main__":
    main()
