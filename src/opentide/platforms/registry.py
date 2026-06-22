"""Platform registry — deployers, validators, and per-platform config."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol, cast


class RuleDeployer(Protocol):
    def deploy(self, deployment: list[str]) -> None: ...


class QueryValidator(Protocol):
    def validate(self, deployment: list[str]) -> None: ...


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
            enabled=enabled if enabled is not None else (existing.enabled if existing else False),
            config=config if config is not None else (existing.config if existing else None),
            deployer=self._deployers.get(name),
            validator=self._validators.get(name),
        )
        self._instances[name] = platform
        return platform

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        import sys

        from opentide.core.root import repository_root

        root = str(repository_root())
        if root not in sys.path:
            sys.path.append(root)

        from Engines.modules.deployment import enabled_systems
        from Engines.modules.registry import OpenTide as LegacyOpenTide

        for system in LegacyOpenTide.Configuration.Systems.Index:
            module_name = system
            try:
                module = importlib.import_module(f"Engines.deployment.{module_name}")
                deployer = module.declare()
                self._deployers[system] = cast(RuleDeployer, deployer)
            except Exception:
                pass

            try:
                module = importlib.import_module(f"Engines.validation.{module_name}_query")
                validator = module.declare()
                self._validators[system] = cast(QueryValidator, validator)
            except Exception:
                pass

            config = getattr(LegacyOpenTide.Configuration.Systems, _class_name(system), None)
            self._instances[system] = Platform(
                name=system,
                enabled=system in enabled_systems(),
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
