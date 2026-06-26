"""Options for rendering client CI pipeline files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentide.cli.enums import CiPlatform, DetectionPlatform
    from opentide.cli.services.setup.ci import CiSetupOptions


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
    docs_output: str = "docs"
    docs_enabled: bool = True
    explorer_pages: bool = False

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
    def from_repo_options(cls, repo: CiSetupOptions, platforms: list[str]) -> CiRenderOptions:
        from opentide import __version__

        return cls(
            ci=repo.ci.value,
            platforms=platforms,
            staging=repo.staging,
            promotion=repo.promotion,
            promotion_target=repo.promotion_target,
            python_version=repo.python_version,
            opentide_version=__version__,
            explorer_pages=repo.explorer_pages,
        )

    @classmethod
    def from_init_options(cls, init: CiSetupOptions) -> CiRenderOptions:
        """Backward-compatible alias for :meth:`from_repo_options`."""
        return cls.from_repo_options(init, [])

    def output_paths(self) -> dict[str, str]:
        """Relative output paths keyed by platform value."""
        return {
            "github": ".github/workflows/opentide.yml",
            "gitlab": ".gitlab-ci.yml",
            "azure": "azure-pipelines.yml",
        }

    def output_path(self) -> str:
        return self.output_paths()[self.ci]
