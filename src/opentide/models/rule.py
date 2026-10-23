"""Detection rule (MDR) Pydantic model — schema ``rule::1.0``."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar, Protocol, cast

from pydantic import PrivateAttr

from opentide.models.base import FieldRole, TideField, TideModel
from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES
from opentide.models.metadata import ObjectMetadata, ObjectReferences, RuleMetadata
from opentide.models.platform import RuleConfigurations
from opentide.models.response import RuleResponse
from opentide.models.results import DeploymentResult, ValidationResult

#: Environment flags a platform query validator raises on a failure or a warning.
_ERROR_FLAG = "VALIDATION_ERROR_RAISED"
_WARNING_FLAG = "VALIDATION_WARNING_RAISED"
_QUERY_VALIDATION_FLAGS = (_ERROR_FLAG, _WARNING_FLAG)


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
    metadata: ObjectMetadata = TideField(schema_extra={"tide.template.spacer": True})
    description: str = TideField(
        schema_extra={"tide.template.multiline": True, "tide.template.spacer": True}
    )
    status: str = "STAGING"
    severity: str = "Informational"
    techniques: list[str] = TideField(default_factory=list, role=FieldRole.TECHNIQUES)
    platforms: dict[str, dict[str, Any]] = TideField(
        default_factory=dict,
        schema_extra={"tide.template.hide": True},
        role=FieldRole.CONFIGURATIONS,
    )
    references: ObjectReferences | None = None
    detection_model: str | None = None
    response: RuleResponse | None = TideField(None, schema_extra={"tide.template.required": True})
    configurations: RuleConfigurations | None = TideField(
        None, schema_extra={"tide.template.required": True}, role=FieldRole.CONFIGURATIONS
    )
    file: Path | None = TideField(None, schema_extra={"tide.template.hide": True})
    _registry: TideRegistry | None = PrivateAttr(default=None)

    def platform_configs(self) -> RuleConfigurations:
        """``configurations``, or an error naming the rule when it has none.

        Deployers and validators only receive rules the planner selected for
        their platform, so a missing block is a malformed rule; it used to
        surface as ``'NoneType' object has no attribute 'sentinel'``.
        """
        if self.configurations is None:
            raise ValueError(f"Rule {self.metadata.uuid} ({self.name}) has no configurations block")
        return self.configurations

    @property
    def alert_severity(self) -> str:
        """``response.alert_severity``, or its default when the rule has no response."""
        if self.response is None:
            return RuleResponse.model_fields["alert_severity"].default
        return self.response.alert_severity

    def bind_registry(self, registry: TideRegistry) -> DetectionRule:
        """Return a copy with registry back-reference for delegation."""
        bound = self.model_copy(deep=True)
        bound._registry = registry
        return cast(DetectionRule, bound)

    def deploy(
        self,
        platform: str,
        dry_run: bool = False,
        *,
        strategies: Iterable[str] | None = None,
    ) -> DeploymentResult:
        """Deploy this rule to *platform*'s tenants that accept the run's strategies.

        *strategies* are run strategies (``PREVIEW``, ``RELEASE``). ``None``
        deploys the rule as its platform status says: the runs that deploy the
        strategy its status maps to.
        """
        if self._registry is None:
            raise RuntimeError("DetectionRule.deploy() requires a bound registry")
        platforms = self._registry.Platforms
        if platform not in platforms:
            raise ValueError(f"Unknown platform {platform!r}")
        entry = platforms[platform]
        deployer = getattr(entry, "deployer", None)
        if deployer is None:
            raise ValueError(f"Platform {platform!r} has no deployer")
        uuid = self.metadata.uuid
        if dry_run:
            return DeploymentResult(
                platform=platform, uuids=[uuid], dry_run=True, message="dry-run"
            )
        from opentide.models.deployment_enums import deployed_by, parse_strategies

        if strategies is None:
            from opentide.deployment.utils import check_status

            block = getattr(self.configurations, platform, None)
            status = getattr(block, "status", None)
            if not status:
                raise ValueError(f"Rule {self.name!r} has no {platform} status to deploy")
            run = deployed_by(check_status(str(status)))
        else:
            run = parse_strategies(strategies)
        deployer.deploy([uuid], run)
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
        # Platform validators log each refused query and report the verdict
        # only through these process-wide flags, which the CLI grades after a
        # run. Clear them for the call so an earlier failure does not fail
        # this rule, then put back what was there so the caller's run keeps
        # its own verdict.
        saved = {flag: os.environ.get(flag) for flag in _QUERY_VALIDATION_FLAGS}
        for flag in _QUERY_VALIDATION_FLAGS:
            os.environ[flag] = ""
        try:
            # The CLI default: without strategies no tenant is targeted and
            # nothing would be checked (and most validators required them).
            validator.validate([self.metadata.uuid], DEPLOYABLE_STRATEGIES)
            failed = bool(os.environ.get(_ERROR_FLAG))
            warned = bool(os.environ.get(_WARNING_FLAG))
        finally:
            for flag, value in saved.items():
                if value is None:
                    os.environ.pop(flag, None)
                else:
                    os.environ[flag] = value
        return ValidationResult(
            ok=not failed,
            errors=[f"Query validation failed for {platform}"] if failed else [],
            warnings=[f"Query validation reported warnings for {platform}"] if warned else [],
        )

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


class DetectionRule_v1_1(DetectionRule):
    """Detection rule schema ``rule::1.1`` with optional ``metadata.reviewed``."""

    __schema_identifier__: ClassVar[str] = "rule::1.1"
    metadata: RuleMetadata = TideField(schema_extra={"tide.template.spacer": True})
