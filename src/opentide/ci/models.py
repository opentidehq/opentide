"""Options for rendering client CI pipeline files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentide.cli.enums import CiPlatform, DetectionPlatform
    from opentide.cli.services.init import InitOptions


@dataclass
class CiRenderOptions:
    """Configuration passed to GitHub, GitLab, and Azure renderers."""

    ci: str
    platforms: list[str] = field(default_factory=list)
    staging: bool = True
    promotion: bool = True
    promotion_target: str = "PRODUCTION"
    python_version: str = "3.12"
    opentide_version: str = "0.1.0"
    default_branch: str = "main"

    @classmethod
    def from_init(
        cls,
        ci: CiPlatform,
        platforms: list[DetectionPlatform],
        staging: bool,
        promotion: bool,
        promotion_target: str,
        python_version: str = "3.12",
        opentide_version: str | None = None,
        default_branch: str = "main",
    ) -> CiRenderOptions:
        from opentide import __version__

        return cls(
            ci=ci.value,
            platforms=[p.value for p in platforms],
            staging=staging,
            promotion=promotion,
            promotion_target=promotion_target,
            python_version=python_version,
            opentide_version=opentide_version or __version__,
            default_branch=default_branch,
        )

    @classmethod
    def from_init_options(cls, init: InitOptions) -> CiRenderOptions:
        return cls.from_init(
            ci=init.ci,
            platforms=init.platforms,
            staging=init.staging,
            promotion=init.promotion,
            promotion_target=init.promotion_target,
        )

    def output_paths(self) -> dict[str, str]:
        """Relative output paths keyed by platform value."""
        return {
            "github": ".github/workflows/opentide.yml",
            "gitlab": ".gitlab-ci.yml",
            "azure": "azure-pipelines.yml",
        }

    def output_path(self) -> str:
        return self.output_paths()[self.ci]
