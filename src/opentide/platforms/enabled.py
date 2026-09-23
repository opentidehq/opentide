"""Enabled platform discovery from merged configuration."""

from __future__ import annotations

from collections.abc import Iterable

from opentide.core.files import resolve_configurations
from opentide.registry.discovery import OPENTIDE_DIR, client_configurations_dir, discover_workspace

SYSTEM_KEYS = (
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "carbon_black_cloud",
)


def enabled_systems() -> list[str]:
    """Return platform identifiers marked enabled in merged system configuration."""
    systems = resolve_configurations().get("systems", {})
    enabled: list[str] = []
    for system in SYSTEM_KEYS:
        config = systems.get(system)
        if not config:
            continue
        tide_block = config.get("tide", {})
        platform_block = config.get("platform", {})
        if tide_block.get("enabled") is True or platform_block.get("enabled") is True:
            enabled.append(system)
    return enabled


def systems_without_tenants(systems: Iterable[str]) -> list[str]:
    """Return the *systems* whose merged configuration declares no ``[[tenants]]`` table."""
    configs = resolve_configurations().get("systems", {})
    missing: list[str] = []
    for system in systems:
        tenants = (configs.get(system) or {}).get("tenants")
        if not isinstance(tenants, list) or not any(isinstance(t, dict) for t in tenants):
            missing.append(system)
    return missing


def platform_config_path(system: str) -> str:
    """Workspace-relative TOML that configures *system* (where setup writes it if absent)."""
    workspace = discover_workspace()
    configs = client_configurations_dir(workspace)
    for folder in ("platforms", "systems"):
        candidate = configs / folder / f"{system}.toml"
        if candidate.is_file():
            return candidate.relative_to(workspace).as_posix()
    return f"{OPENTIDE_DIR}/configurations/platforms/{system}.toml"


class MissingTenantsError(ValueError):
    """An enabled platform has rules in scope but no tenant to send them to."""

    def __init__(self, system: str, config_path: str | None = None) -> None:
        self.system = system
        self.config_path = config_path or platform_config_path(system)
        super().__init__(f"{system} has no tenants configured in {self.config_path}")

    @property
    def advice(self) -> str:
        return f"add (or uncomment) a [[tenants]] entry in {self.config_path}"
