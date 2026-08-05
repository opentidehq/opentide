"""Platform configuration scaffolding for client repositories."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from opentide.cli.enums import DetectionPlatform
from opentide.package.paths import bundled_configurations_root
from opentide.registry.discovery import OPENTIDE_DIR

logger = structlog.get_logger("opentide.cli.services.setup.platforms")

_PLATFORM_TOML: dict[DetectionPlatform, str] = {
    DetectionPlatform.sentinel: "sentinel.toml",
    DetectionPlatform.splunk: "splunk.toml",
    DetectionPlatform.crowdstrike: "crowdstrike.toml",
    DetectionPlatform.defender: "defender_for_endpoint.toml",
    DetectionPlatform.sentinel_one: "sentinel_one.toml",
    DetectionPlatform.carbon_black: "carbon_black_cloud.toml",
    DetectionPlatform.harfanglab: "harfanglab.toml",
}


@dataclass
class PlatformsSetupOptions:
    """Non-interactive platform configuration setup."""

    path: Path = Path(".")
    platforms: list[DetectionPlatform] = field(default_factory=list)
    yes: bool = False


def _enable_platform_toml(content: str) -> str:
    if re.search(r"^enabled\s*=", content, re.MULTILINE):
        return re.sub(
            r"^enabled\s*=\s*\w+\s*$", "enabled = true", content, count=1, flags=re.MULTILINE
        )
    return content.replace("[platform]", "[platform]\nenabled = true", 1)


def run_platforms_setup(options: PlatformsSetupOptions) -> dict[str, object]:
    """Copy bundled platform templates and enable selected platforms."""
    if not options.platforms:
        raise ValueError("Choose at least one platform")
    target = options.path.resolve()
    dest = target / OPENTIDE_DIR / "configurations" / "platforms"
    dest.mkdir(parents=True, exist_ok=True)
    template_root = bundled_configurations_root() / "platforms"
    written: list[str] = []
    for platform in options.platforms:
        template_name = _PLATFORM_TOML[platform]
        template_path = template_root / template_name
        if not template_path.is_file():
            logger.warning(
                "platform_template_missing", platform=platform.value, path=str(template_path)
            )
            continue
        content = _enable_platform_toml(template_path.read_text(encoding="utf-8"))
        out_path = dest / template_name
        out_path.write_text(content, encoding="utf-8")
        written.append(str(out_path.relative_to(target)))
    logger.debug(
        "platform_configs_created", path=str(target), platforms=[p.value for p in options.platforms]
    )
    return {
        "message": "Platform configuration files created",
        "path": str(target),
        "platforms": [p.value for p in options.platforms],
        "files": written,
    }
