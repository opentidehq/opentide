"""The Tide models of ``opentide.models.platform``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
"""

from __future__ import annotations

from opentide._native.models import (
    CarbonBlackConfig,
    CrowdstrikeConfig,
    DefenderConfig,
    ElasticConfig,
    GoogleSecopsConfig,
    GoogleSecopsMatch,
    GoogleSecopsOptions,
    GoogleSecopsSchedule,
    GraylogConfig,
    HarfangLabConfig,
    RuleConfigurations,
    SentinelConfig,
    SentinelOneConfig,
    SplunkConfig,
    SysdigConfig,
)

__all__ = [
    "CarbonBlackConfig",
    "CrowdstrikeConfig",
    "DefenderConfig",
    "ElasticConfig",
    "GoogleSecopsConfig",
    "GoogleSecopsMatch",
    "GoogleSecopsOptions",
    "GoogleSecopsSchedule",
    "GraylogConfig",
    "HarfangLabConfig",
    "RuleConfigurations",
    "SentinelConfig",
    "SentinelOneConfig",
    "SplunkConfig",
    "SysdigConfig",
]
