"""Platform registry — deployers, validators, and per-platform config."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable, Iterator, Sequence
from functools import partial
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Generic, Protocol, TypeVar, cast

from opentide.core.logging import get_logger
from opentide.core.root import get_repo_root
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.config import build_system_config
from opentide.platforms.enabled import enabled_systems

logger = get_logger(__name__)

_VALIDATOR_MODULES = {
    "sentinel": "sentinel_query",
    "defender_for_endpoint": "defender_for_endpoint_query",
    "splunk": "splunk_query",
    "sentinel_one": "sentinel_one_query",
    "carbon_black_cloud": "carbon_black_cloud_query",
}

_PLATFORM_PACKAGES = {
    "carbon_black_cloud": "carbon_black",
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


T = TypeVar("T")


class _Deferred(Generic[T]):
    """A value built by *factory* the first time it is read."""

    def __init__(self, value: T | None = None, factory: Callable[[], T] | None = None) -> None:
        self._value = value
        self._factory = factory

    @property
    def available(self) -> bool:
        return self._value is not None or self._factory is not None

    def get(self, *, platform: str, part: str) -> T | None:
        if self._factory is not None:
            factory, self._factory = self._factory, None
            try:
                self._value = factory()
            except Exception as exc:
                logger.debug(
                    "platform_part_unavailable", platform=platform, part=part, detail=repr(exc)
                )
        return self._value


class Platform:
    """A detection platform's configuration and operational capabilities.

    ``config``, ``deployer`` and ``validator`` are built on first access, so
    listing platforms never reads the tenant configuration of a platform that
    is not used: building a client resolves its secrets and checks its setup,
    which logs for every platform that is disabled or not configured.
    """

    def __init__(
        self,
        name: str,
        enabled: bool = False,
        config: Any | None = None,
        deployer: RuleDeployer | None = None,
        validator: QueryValidator | None = None,
        *,
        config_factory: Callable[[], Any] | None = None,
        deployer_factory: Callable[[], RuleDeployer] | None = None,
        validator_factory: Callable[[], QueryValidator] | None = None,
    ) -> None:
        self.name = name
        self.enabled = enabled
        self._config = _Deferred(config, config_factory)
        self._deployer = _Deferred(deployer, deployer_factory)
        self._validator = _Deferred(validator, validator_factory)

    def __repr__(self) -> str:
        return f"Platform(name={self.name!r}, enabled={self.enabled!r})"

    @property
    def config(self) -> Any | None:
        return self._config.get(platform=self.name, part="config")

    @config.setter
    def config(self, value: Any | None) -> None:
        self._config = _Deferred(value)

    @property
    def deployer(self) -> RuleDeployer | None:
        return self._deployer.get(platform=self.name, part="deployer")

    @deployer.setter
    def deployer(self, value: RuleDeployer | None) -> None:
        self._deployer = _Deferred(value)

    @property
    def validator(self) -> QueryValidator | None:
        return self._validator.get(platform=self.name, part="validator")

    @validator.setter
    def validator(self, value: QueryValidator | None) -> None:
        self._validator = _Deferred(value)

    @property
    def can_deploy(self) -> bool:
        return self._deployer.available

    @property
    def can_validate(self) -> bool:
        return self._validator.available


def _class_name(system_key: str) -> str:
    return "".join(part.capitalize() for part in system_key.split("_"))


def _ensure_repo_on_path() -> None:
    root = str(get_repo_root())
    if root not in sys.path:
        sys.path.append(root)


def _deployer_factory(ep: EntryPoint) -> Callable[[], RuleDeployer] | None:
    try:
        return cast(Callable[[], RuleDeployer], ep.load())
    except Exception:
        # Entry point may be missing or fail to load for optional platforms.
        return None


class PlatformsRegistry:
    """First-class platform access with explicit registration."""

    def __init__(self) -> None:
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
        platform = self._instances.get(name) or Platform(name=name)
        if deployer is not None:
            platform.deployer = deployer
        if validator is not None:
            platform.validator = validator
        if config is not None:
            platform.config = config
        if enabled is not None:
            platform.enabled = enabled
        self._instances[name] = platform
        return platform

    def _validator_factory(self, system: str) -> Callable[[], QueryValidator] | None:
        candidates: list[str] = []
        module_suffix = _VALIDATOR_MODULES.get(system)
        if module_suffix is not None:
            candidates.append(f"opentide.validation.{module_suffix}")
        pkg = _PLATFORM_PACKAGES.get(system, system)
        candidates.append(f"opentide.platforms.{pkg}.validator")
        _ensure_repo_on_path()
        for module_name in dict.fromkeys(candidates):
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            declare = getattr(module, "declare", None)
            if callable(declare):
                return cast(Callable[[], QueryValidator], declare)
        return None

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        _ensure_repo_on_path()
        active = set(enabled_systems())
        eps = entry_points(group="opentide.platforms")
        for ep in eps:
            system = ep.name.replace("-", "_")
            self._instances[system] = Platform(
                name=system,
                enabled=system in active,
                config_factory=partial(build_system_config, system),
                deployer_factory=_deployer_factory(ep),
                validator_factory=self._validator_factory(system),
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
        built = {name: platform.deployer for name, platform in self._instances.items()}
        return {name: deployer for name, deployer in built.items() if deployer is not None}

    def validators(self) -> dict[str, QueryValidator]:
        self._ensure_loaded()
        built = {name: platform.validator for name, platform in self._instances.items()}
        return {name: validator for name, validator in built.items() if validator is not None}

    def __contains__(self, name: str) -> bool:
        self._ensure_loaded()
        return name in self._instances

    def items(self) -> Iterator[tuple[str, Platform]]:
        self._ensure_loaded()
        yield from self._instances.items()
