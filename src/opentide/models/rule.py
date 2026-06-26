"""Detection rule (MDR) Pydantic model — schema ``rule::1.0``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, Protocol, cast

from pydantic import Field, PrivateAttr

from opentide.models.base import TideModel
from opentide.models.metadata import ObjectMetadata, ObjectReferences
from opentide.models.platform import RuleConfigurations
from opentide.models.response import RuleResponse
from opentide.models.results import DeploymentResult, ValidationResult


class TideRegistry(Protocol):
    """Minimal registry surface injected at load time for delegation methods."""

    Platforms: Any

    def validate_rule(self, rule: DetectionRule) -> ValidationResult:
        pass

    def document_rule(self, rule: DetectionRule) -> str:
        pass

    def render_rule(self, rule: DetectionRule) -> str:
        pass

    def promote_rule(self, rule: DetectionRule, target_status: str) -> None:
        pass


class DetectionRule(TideModel):
    """Code-first detection rule with registry-backed delegation helpers."""

    __schema_identifier__: ClassVar[str] = "rule::1.0"
    name: str
    metadata: ObjectMetadata
    description: str
    status: str = "STAGING"
    severity: str = "Informational"
    techniques: list[str] = Field(default_factory=list)
    platforms: dict[str, dict[str, Any]] = Field(default_factory=dict)
    references: ObjectReferences | None = None
    detection_model: str | None = None
    response: RuleResponse | None = None
    configurations: RuleConfigurations | None = None
    file: Path | None = None
    _registry: TideRegistry | None = PrivateAttr(default=None)

    def bind_registry(self, registry: TideRegistry) -> DetectionRule:
        """Return a copy with registry back-reference for delegation."""
        bound = self.model_copy(deep=True)
        bound._registry = registry
        return cast(DetectionRule, bound)

    def deploy(self, platform: str, dry_run: bool = False) -> DeploymentResult:
        if self._registry is None:
            raise RuntimeError("DetectionRule.deploy() requires a bound registry")
        entry = self._registry.Platforms[platform]
        deployer = getattr(entry, "deployer", None)
        if deployer is None:
            raise ValueError(f"Platform {platform!r} has no deployer")
        uuid = self.metadata.uuid
        if dry_run:
            return DeploymentResult(
                platform=platform, uuids=[uuid], dry_run=True, message="dry-run"
            )
        deployer.deploy([uuid])
        return DeploymentResult(platform=platform, uuids=[uuid], dry_run=False)

    def validate(self) -> ValidationResult:  # ty: ignore[invalid-method-override]
        if self._registry is None:
            raise RuntimeError("DetectionRule.validate() requires a bound registry")
        return self._registry.validate_rule(self)

    def validate_query(self, platform: str) -> ValidationResult:
        if self._registry is None:
            raise RuntimeError("DetectionRule.validate_query() requires a bound registry")
        platforms = self._registry.Platforms
        if platform not in platforms:
            return ValidationResult(ok=False, errors=[f"Unknown platform {platform!r}"])
        entry = platforms[platform]
        validator = getattr(entry, "validator", None)
        if validator is None:
            return ValidationResult(
                ok=False, errors=[f"Platform {platform!r} does not support query validation"]
            )
        validator.validate([self.metadata.uuid])
        return ValidationResult(ok=True)

    def document(self) -> str:
        if self._registry is None:
            raise RuntimeError("DetectionRule.document() requires a bound registry")
        render = getattr(self._registry, "render_rule", None)
        if callable(render):
            return render(self)
        return self._registry.document_rule(self)

    def promote(self, target_status: str) -> None:
        if self._registry is None:
            raise RuntimeError("DetectionRule.promote() requires a bound registry")
        self._registry.promote_rule(self, target_status)

    @classmethod
    def from_yaml_dict(cls, payload: dict[str, Any], *, file: Path | None = None) -> DetectionRule:
        references = payload.get("references")
        if references is not None:
            payload = dict(payload)
            payload["references"] = ObjectReferences.coerce_public_keys(references)
        rule = cls.model_validate(payload)
        if file is not None:
            return cast(DetectionRule, rule.model_copy(update={"file": file}))
        return cast(DetectionRule, rule)
