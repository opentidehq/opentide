"""Live query validation for Splunk: each rule's deployed search, parsed by its tenants.

The check is Splunk's ``search/parser`` (the runner's ``check``), with macros
and lookups resolved, so no search job runs.
"""

from __future__ import annotations

from typing import ClassVar

from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.platforms.live_validation import LiveQueryValidator


class SplunkQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "splunk"

    def host(self, tenant: SystemConfig.Tenant) -> str:
        if isinstance(tenant, ConfigurationModels.Systems.Splunk.Tenant):
            return f"{tenant.setup.url}:{tenant.setup.port}"
        return super().host(tenant)


def declare() -> SplunkQueryValidator:
    return SplunkQueryValidator()
