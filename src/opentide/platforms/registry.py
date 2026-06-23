"""Platform registry — deployers, validators, and per-platform config."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any, Protocol, cast

from opentide.core.root import get_repo_root
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.config import build_system_config
from opentide.platforms.enabled import enabled_systems

_VALIDATOR_MODULES = {
    "sentinel": "sentinel_query",
    "defender_for_endpoint": "defender_for_endpoint_query",
    "splunk": "splunk_query",
    "sentinel_one": "sentinel_one_query",
    "carbon_black_cloud": "carbon_black_cloud_query",
}


class RuleDeployer(Protocol):
    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        pass


class QueryValidator(Protocol):
    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        pass


@dataclass
class Platform:
    """A detection platform's configuration and operational capabilities."""

    name: str
    enabled: bool = False
    config: Any | None = None
    deployer: RuleDeployer | None = None
    validator: QueryValidator | None = None

    @property
    def can_deploy(self) -> bool:
        return self.deployer is not None

    @property
    def can_validate(self) -> bool:
        return self.validator is not None


def _class_name(system_key: str) -> str:
    return "".join(part.capitalize() for part in system_key.split("_"))


def _ensure_repo_on_path() -> None:
    root = str(get_repo_root())
    if root not in sys.path:
        sys.path.append(root)


class PlatformsRegistry:
    """First-class platform access with explicit registration."""

    def __init__(self) -> None:
        self._deployers: dict[str, RuleDeployer] = {}
        self._validators: dict[str, QueryValidator] = {}
        self._instances: dict[str, Platform] = {}
        self._loaded = False

    def register(
        self,
        name: str,
        *,
        deployer: RuleDeployer | None = None,
        validator: QueryValidator | None = None,
        config: Any | None = None,
        enabled: bool | None = None,
    ) -> Platform:
        """Register or update a platform's operational engines."""
        if deployer is not None:
            self._deployers[name] = deployer
        if validator is not None:
            self._validators[name] = validator
        existing = self._instances.get(name)
        platform = Platform(
            name=name,
            enabled=enabled if enabled is not None else existing.enabled if existing else False,
            config=config if config is not None else existing.config if existing else None,
            deployer=self._deployers.get(name),
            validator=self._validators.get(name),
        )
        self._instances[name] = platform
        return platform

    def _load_validator(self, system: str) -> QueryValidator | None:
        module_suffix = _VALIDATOR_MODULES.get(system)
        if module_suffix is None:
            return None
        _ensure_repo_on_path()
        try:
            module = importlib.import_module(f"opentide.validation.{module_suffix}")
            return cast(QueryValidator, module.declare())
        except Exception:
            return None

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        _ensure_repo_on_path()
        active = set(enabled_systems())
        eps = entry_points(group="opentide.platforms")
        for ep in eps:
            system = ep.name.replace("-", "_")
            try:
                deployer = cast(RuleDeployer, ep.load()())
                self._deployers[system] = deployer
            except Exception:
                # Entry point may be missing or fail to load for optional platforms.
                pass
            validator = self._load_validator(system)
            if validator is not None:
                self._validators[system] = validator
            try:
                config = build_system_config(system)
            except Exception:
                config = None
            self._instances[system] = Platform(
                name=system,
                enabled=system in active,
                config=config,
                deployer=self._deployers.get(system),
                validator=self._validators.get(system),
            )
        self._loaded = True

    def __getitem__(self, name: str) -> Platform:
        self._ensure_loaded()
        if name not in self._instances:
            raise KeyError(name)
        return self._instances[name]

    def __getattr__(self, name: str) -> Platform:
        if name.startswith("_"):
            raise AttributeError(name)
        self._ensure_loaded()
        if name in self._instances:
            return self._instances[name]
        for key, platform in self._instances.items():
            if _class_name(key) == name:
                return platform
        raise AttributeError(name)

    def enabled(self) -> Iterator[Platform]:
        self._ensure_loaded()
        for platform in self._instances.values():
            if platform.enabled:
                yield platform

    def deployers(self) -> dict[str, RuleDeployer]:
        self._ensure_loaded()
        return dict(self._deployers)

    def validators(self) -> dict[str, QueryValidator]:
        self._ensure_loaded()
        return dict(self._validators)

    def __contains__(self, name: str) -> bool:
        self._ensure_loaded()
        return name in self._instances

    def items(self) -> Iterator[tuple[str, Platform]]:
        self._ensure_loaded()
        yield from self._instances.items()
