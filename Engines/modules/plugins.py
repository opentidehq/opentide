"""Backward-compatibility shim — platform engines live in platforms.py."""

from Engines.modules.platforms import (
    Platform,
    Platforms,
    PlatformLoader,
    PlatformEngine,
    PlatformEngineBase,
    ValidationEngine,
    RuleDeployer,
    QueryValidator,
    DeployTide,
    DeployMDR,
    DeployEngine,
    ValidateQuery,
    PluginTide,
    PluginEnginesLoader,
    PlatformsRegistry,
)

__all__ = [
    "Platform",
    "Platforms",
    "PlatformLoader",
    "PlatformEngine",
    "PlatformEngineBase",
    "ValidationEngine",
    "RuleDeployer",
    "QueryValidator",
    "DeployTide",
    "DeployMDR",
    "DeployEngine",
    "ValidateQuery",
    "PluginTide",
    "PluginEnginesLoader",
    "PlatformsRegistry",
]
