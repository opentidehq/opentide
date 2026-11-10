"""The Tide models of ``opentide.models.platform``: the Rust classes (ADR 0011).

Each class is the frozen Rust model of the same name (``opentide._native.models``).
The module's other names, which are the Pydantic package's (``opentide._models.platform``),
still resolve, with a ``DeprecationWarning``, for one minor release.
"""

from __future__ import annotations

from opentide._native.models import (
    CarbonBlackConfig,
    CrowdstrikeConfig,
    DefenderConfig,
    ElasticConfig,
    HarfangLabConfig,
    RuleConfigurations,
    SentinelConfig,
    SentinelOneConfig,
    SplunkConfig,
    SysdigConfig,
)
from opentide.models._compat import deprecated_attribute

__all__ = [
    "CarbonBlackConfig",
    "CrowdstrikeConfig",
    "DefenderConfig",
    "ElasticConfig",
    "HarfangLabConfig",
    "RuleConfigurations",
    "SentinelConfig",
    "SentinelOneConfig",
    "SplunkConfig",
    "SysdigConfig",
]


def __getattr__(name: str) -> object:
    return deprecated_attribute(__name__, "opentide._models.platform", name)
