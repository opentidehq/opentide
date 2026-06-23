"""Detection platform registry — deployers, validators, and per-platform config."""
from __future__ import annotations
import importlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from collections.abc import Sequence
from typing import Iterator, cast
import structlog

from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule

logger = structlog.get_logger('opentide.platforms.plugins')

class PlatformEngineBase(ABC):
    """Base type for platform operational engines."""

class PlatformEngine(PlatformEngineBase):
    """Engine tier for deployment operations."""

class ValidationEngine(PlatformEngineBase):
    """Engine tier for query validation operations."""

class RuleDeployer(PlatformEngine):

    @abstractmethod
    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy detection rules onto the target platform."""

class QueryValidator(ValidationEngine):

    @abstractmethod
    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ):
        """Validate that queries can be executed on the target platform."""

class PlatformLoader:
    """Loads platform deployer and validator engine classes."""

    class EngineModule:

        @staticmethod
        def declare():
            """Registers the engine class for a platform."""
            pass

    @staticmethod
    def import_engine(module_path: str) -> EngineModule:
        return importlib.import_module(module_path)

    def _load_engines(self, tier: PlatformEngineBase, identifier: str) -> dict[str, type]:
        logger.info('initiating_platform_engine_loading')
        engines: dict[str, type] = {}
        from opentide.core.registry import OpenTide
        for system in OpenTide.Configuration.Systems.Index:
            module_name = system + identifier
            pkg = _platform_pkg(system)
            module = None
            try:
                if isinstance(tier, PlatformEngine):
                    logger.info('loading_deployment_engine', arg0=module_name)
                    module = self.import_engine(f'opentide.platforms.{pkg}.deployer')
                elif isinstance(tier, ValidationEngine):
                    logger.info('loading_validation_engine', arg0=module_name)
                    module = self.import_engine(f'opentide.platforms.{pkg}.validator')
                else:
                    logger.critical('unsupported_engine_tier', detail=str(tier))
            except Exception as exc:
                logger.warning('failed_to_import_platform_engine', detail=repr(exc), advice=module_name)
            if module:
                try:
                    engines[system] = module.declare()
                except Exception as exc:
                    logger.critical('engine_module_missing_declare', arg0=module_name, advice=repr(exc))
                    raise Exception('PLATFORM ENGINE IMPORT ERROR') from exc
                logger.info('loaded_platform_engine', arg0=module_name)
        return engines

    def rule_deployers(self) -> dict[str, RuleDeployer]:
        return cast(dict[str, RuleDeployer], self._load_engines(identifier='', tier=PlatformEngine()))

    def query_validators(self) -> dict[str, QueryValidator]:
        return cast(dict[str, QueryValidator], self._load_engines(identifier='_query', tier=ValidationEngine()))

@dataclass
class Platform:
    """A detection platform's configuration and operational capabilities."""
    name: str
    enabled: bool = False
    config: object | None = None
    deployer: RuleDeployer | None = None
    validator: QueryValidator | None = None

    @property
    def can_deploy(self) -> bool:
        return self.deployer is not None

    @property
    def can_validate(self) -> bool:
        return self.validator is not None

class _PlatformsAccessor:
    """First-class platform access on OpenTide."""
    _deployers: dict[str, RuleDeployer] | None = None
    _validators: dict[str, QueryValidator] | None = None
    _instances: dict[str, Platform] | None = None

    def _ensure_loaded(self) -> None:
        if self._deployers is None:
            from opentide.deployment import enabled_systems
            from opentide.core.registry import OpenTide
            loader = PlatformLoader()
            self._deployers = loader.rule_deployers()
            self._validators = loader.query_validators()
            self._instances = {}
            systems_index = OpenTide.Configuration.Systems.Index
            for name in systems_index:
                self._instances[name] = Platform(name=name, enabled=name in enabled_systems(), config=getattr(OpenTide.Configuration.Systems, _class_name(name), None), deployer=self._deployers.get(name), validator=self._validators.get(name))

    def __getitem__(self, name: str) -> Platform:
        self._ensure_loaded()
        assert self._instances is not None
        if name not in self._instances:
            raise KeyError(name)
        return self._instances[name]

    def enabled(self) -> Iterator[Platform]:
        self._ensure_loaded()
        assert self._instances is not None
        for platform in self._instances.values():
            if platform.enabled:
                yield platform

    def deployers(self) -> dict[str, RuleDeployer]:
        self._ensure_loaded()
        assert self._deployers is not None
        return self._deployers

    def validators(self) -> dict[str, QueryValidator]:
        self._ensure_loaded()
        assert self._validators is not None
        return self._validators

    def __getattr__(self, name: str) -> Platform:
        if name.startswith('_'):
            raise AttributeError(name)
        self._ensure_loaded()
        assert self._instances is not None
        if name in self._instances:
            return self._instances[name]
        for key, platform in self._instances.items():
            if _class_name(key) == name:
                return platform
        raise AttributeError(name)
Platforms = _PlatformsAccessor()

def _class_name(system_key: str) -> str:
    """Map systems index key to Configuration.Systems nested class name."""
    return ''.join((part.capitalize() for part in system_key.split('_')))
PluginTide = PlatformEngineBase
DeployEngine = PlatformEngine
DeployMDR = RuleDeployer
ValidateQuery = QueryValidator
PluginEnginesLoader = PlatformLoader

class DeployTide:
    """Deprecated — use OpenTide.Platforms."""

    @staticmethod
    def _enabled_keys() -> set[str]:
        from opentide.deployment import enabled_systems
        return set(enabled_systems())

    @property
    def mdr(self) -> dict[str, RuleDeployer]:
        enabled = self._enabled_keys()
        return {k: v for k, v in Platforms.deployers().items() if k in enabled}

    @property
    def query_validation(self) -> dict[str, QueryValidator]:
        enabled = self._enabled_keys()
        return {k: v for k, v in Platforms.validators().items() if k in enabled}
PlatformsRegistry = DeployTide
_PLATFORM_PKG: dict[str, str] = {'carbon_black_cloud': 'carbon_black', 'defender_for_endpoint': 'defender_for_endpoint', 'sentinel_one': 'sentinel_one', 'crowdstrike': 'crowdstrike', 'harfanglab': 'harfanglab', 'sentinel': 'sentinel', 'splunk': 'splunk'}

def _platform_pkg(system: str) -> str:
    return _PLATFORM_PKG.get(system, system)
