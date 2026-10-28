"""Read-only queries on platform tenants: ``opentide query``, MCP ``run_query``.

Exports resolve on first access, so ``opentide query --help`` and completion,
which import :mod:`opentide.query.models`, load no engine module.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentide.query.models import (
        DEFAULT_LIMIT,
        MAX_LIMIT,
        QueryColumn,
        QueryRefused,
        QueryRequest,
        QueryResult,
        TenantOutcome,
        TimeWindow,
    )
    from opentide.query.runner import QUERY_PLATFORMS, QueryRunner, load_runner
    from opentide.query.service import QueryRun, QueryUsageError, run_query

_EXPORTS = {
    "DEFAULT_LIMIT": "opentide.query.models",
    "MAX_LIMIT": "opentide.query.models",
    "QueryColumn": "opentide.query.models",
    "QueryRefused": "opentide.query.models",
    "QueryRequest": "opentide.query.models",
    "QueryResult": "opentide.query.models",
    "TenantOutcome": "opentide.query.models",
    "TimeWindow": "opentide.query.models",
    "QUERY_PLATFORMS": "opentide.query.runner",
    "QueryRunner": "opentide.query.runner",
    "load_runner": "opentide.query.runner",
    "QueryRun": "opentide.query.service",
    "QueryUsageError": "opentide.query.service",
    "run_query": "opentide.query.service",
}

__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "QUERY_PLATFORMS",
    "QueryColumn",
    "QueryRefused",
    "QueryRequest",
    "QueryResult",
    "QueryRun",
    "QueryRunner",
    "QueryUsageError",
    "TenantOutcome",
    "TimeWindow",
    "load_runner",
    "run_query",
]


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)
