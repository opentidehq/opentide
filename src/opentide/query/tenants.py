"""Which configured tenants ``opentide query --tenant`` names."""

from __future__ import annotations

from collections.abc import Sequence

from opentide.models.system_config import SystemConfig

#: ``--tenant all`` runs the query on every configured tenant.
ALL_TENANTS = "all"


class TenantSelectionError(ValueError):
    """``--tenant`` names nothing usable; ``choices`` are the configured names."""

    def __init__(self, message: str, *, value: str | None = None, choices: Sequence[str] = ()):
        super().__init__(message)
        self.value = value
        self.choices = tuple(choices)


def configured_tenants(platform: str) -> list[SystemConfig.Tenant]:
    """The ``[[tenants]]`` of *platform*'s configuration, in file order."""
    from opentide.platforms.config import build_system_config

    config = build_system_config(platform)
    return list(getattr(config, "tenants", None) or ())


def select_tenants(
    platform: str,
    names: Sequence[str],
    tenants: Sequence[SystemConfig.Tenant] | None = None,
) -> list[SystemConfig.Tenant]:
    """The tenants *names* select, in configuration order.

    No name selects the only tenant; with several, the caller must name them
    or pass ``all``, so a query never reaches a production tenant unasked.
    """
    available = list(configured_tenants(platform) if tenants is None else tenants)
    known = [tenant.name for tenant in available]
    if not available:
        from opentide.platforms.enabled import platform_config_path

        raise TenantSelectionError(
            f"{platform} has no tenants configured: add a [[tenants]] entry in "
            f"{platform_config_path(platform)}"
        )
    wanted = list(dict.fromkeys(name.strip() for name in names if name.strip()))
    if not wanted:
        if len(available) == 1:
            return available
        raise TenantSelectionError(
            f"{platform} has {len(available)} tenants ({', '.join(known)}): name one with "
            f"--tenant, or pass --tenant {ALL_TENANTS}",
            choices=(*known, ALL_TENANTS),
        )
    if ALL_TENANTS in wanted:
        if len(wanted) > 1:
            raise TenantSelectionError(
                f"--tenant {ALL_TENANTS} already selects every tenant; drop the other names",
                value=ALL_TENANTS,
            )
        return available
    unknown = [name for name in wanted if name not in known]
    if unknown:
        raise TenantSelectionError(
            f"{platform} has no tenant named {unknown[0]!r}; configured: {', '.join(known)}",
            value=unknown[0],
            choices=(*known, ALL_TENANTS),
        )
    return [tenant for tenant in available if tenant.name in wanted]
