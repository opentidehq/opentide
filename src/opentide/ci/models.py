"""Options for rendering client CI pipeline files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentide.cli.enums import CiPlatform, DetectionPlatform

    class CiSetupOptions:
        """Placeholder until setup CLI lands on trunk."""

        ci: CiPlatform
        platforms: list[DetectionPlatform]
        staging: bool
        promotion: bool
        promotion_target: str
        python_version: str
else:
    CiSetupOptions = object  # type: ignore[misc,assignment]


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
    def from_repo_options(cls, repo: CiSetupOptions) -> CiRenderOptions:
        return cls.from_init(
            ci=repo.ci,
            platforms=repo.platforms,
            staging=repo.staging,
            promotion=repo.promotion,
            promotion_target=repo.promotion_target,
            python_version=getattr(repo, "python_version", "3.12"),
        )

    @classmethod
    def from_init_options(cls, init: object) -> CiRenderOptions:
        """Build render options from init/onboarding options."""
        from opentide.cli.enums import CiPlatform

        ci = getattr(init, "ci", CiPlatform.github)
        platforms = getattr(init, "platforms", [])
        return cls.from_init(
            ci=ci,
            platforms=platforms if platforms else [],
            staging=getattr(init, "staging", True),
            promotion=getattr(init, "promotion", True),
            promotion_target=getattr(init, "promotion_target", "PRODUCTION"),
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
