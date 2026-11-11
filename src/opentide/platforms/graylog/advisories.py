"""Graylog advisories (graylog-1.0, Advisories): warnings that never reject a rule.

Graylog accepts each of these, but the definition then does not do what its
author most likely meant. ``opentide validate`` reports them as warnings and
``opentide lint`` with its ``queries`` check. ``graylog_title_duplicate`` is a
workspace check (:mod:`opentide.validation.graylog_titles`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from opentide.platforms.graylog.constraints import as_list, list_ok

OVERLAPPING_WINDOW = "graylog_overlapping_window"
ALL_STREAMS = "graylog_all_streams"
TITLE_DUPLICATE = "graylog_title_duplicate"
LEADING_WILDCARD = "graylog_leading_wildcard"

ADVISORY_CODES = frozenset({OVERLAPPING_WINDOW, ALL_STREAMS, TITLE_DUPLICATE})

_BLOCK = ("configurations", "graylog")
_DEFAULT_EVERY = "5m"


@dataclass(frozen=True)
class Advisory:
    code: str
    field_path: tuple[str, ...]
    message: str


def _block(rule: Mapping[str, Any]) -> Mapping[str, Any] | None:
    configurations = rule.get("configurations")
    block = configurations.get("graylog") if isinstance(configurations, Mapping) else None
    return block if isinstance(block, Mapping) else None


def configured_tenants() -> list[Any]:
    """The workspace's Graylog tenants, or none when the platform has no configuration."""
    try:
        from opentide.core.registry import Opentide

        return list(Opentide.Configurations.Systems.Graylog.tenants or [])
    except Exception:  # no or a broken platforms/graylog.toml: no tenant to read
        return []


def targeted_tenants(block: Mapping[str, Any], tenants: Sequence[Any]) -> list[Any]:
    """The tenants among *tenants* a block reaches: those its ``tenants`` names, else all."""
    names = block.get("tenants")
    if isinstance(names, list) and names:
        return [tenant for tenant in tenants if getattr(tenant, "name", None) in names]
    return list(tenants)


def _seconds(value: Any) -> int | None:
    from opentide.platforms.elastic.durations import duration_seconds

    try:
        return duration_seconds(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _overlapping_window(block: Mapping[str, Any]) -> Advisory | None:
    schedule = block.get("schedule")
    if block.get("aggregation") is not None or not isinstance(schedule, Mapping):
        return None
    if schedule.get("cron") is not None or schedule.get("window") is None:
        return None
    window = _seconds(schedule.get("window"))
    every = _seconds(schedule.get("every") or _DEFAULT_EVERY)
    if window is None or every is None or window <= every:
        return None
    return Advisory(
        OVERLAPPING_WINDOW,
        (*_BLOCK, "schedule"),
        f"the window ({schedule['window']}) is longer than the interval "
        f"({schedule.get('every') or _DEFAULT_EVERY}): on a filter, each message alerts once per "
        "overlapping run",
    )


def _all_streams(block: Mapping[str, Any], tenants: Sequence[Any]) -> Advisory | None:
    if not list_ok(block.get("streams")) or not list_ok(block.get("stream_categories")):
        return None  # graylog_list_shape is the finding
    if as_list(block.get("streams")) or as_list(block.get("stream_categories")):
        return None
    reached = targeted_tenants(block, tenants)
    bare = [tenant.name for tenant in reached if not as_list(tenant.setup.streams)]
    if reached and not bare:
        return None
    where = (
        f"tenant(s) {', '.join(bare)} set no streams either"
        if bare
        else "no Graylog tenant is configured to name default streams"
    )
    return Advisory(
        ALL_STREAMS,
        _BLOCK,
        f"the block sets no streams or stream_categories, and {where}: the definition searches "
        "every stream the token's user can read",
    )


def graylog_advisories(
    rule: Mapping[str, Any], tenants: Sequence[Any] | None = None
) -> list[Advisory]:
    """Every advisory the rule's ``graylog`` block, as authored, earns.

    *tenants* are the workspace's Graylog tenants (default: :func:`configured_tenants`).
    """
    block = _block(rule)
    if block is None:
        return []
    found = [
        advisory
        for advisory in (
            _overlapping_window(block),
            _all_streams(block, configured_tenants() if tenants is None else tenants),
        )
        if advisory is not None
    ]
    return found


def leading_wildcard_allowed(
    block: Mapping[str, Any], tenants: Sequence[Any] | None = None
) -> bool:
    """Whether every tenant the block reaches sets ``allow_leading_wildcard = true``.

    Offline, with no tenant, a leading wildcard stays an error (graylog-1.0, Query diagnostics).
    """
    reached = targeted_tenants(block, configured_tenants() if tenants is None else tenants)
    return bool(reached) and all(
        getattr(tenant.setup, "allow_leading_wildcard", False) is True for tenant in reached
    )
