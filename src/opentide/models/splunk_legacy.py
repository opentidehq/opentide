"""splunk::2.x → v3 field normalisation, shared by loading and validation.

``opentide validate`` calls ``SplunkConfig.model_validate`` on raw YAML, while
deploy and docs go through ``load_splunk_config``. When only the loader knew
the 2.x layout, the same rule validated differently on the two paths: flat
``throttling`` / ``notable`` / ``scheduling.frequency`` loaded fine but failed
validation as unknown keys, and ``search`` / ``cron_schedule`` validated but
never reached the deployer (#233). One function, called from both, keeps
them in agreement.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

_FLAT_SCHEDULE_KEYS = ("frequency", "cron", "custom_time")


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _normalise_scheduling(scheduling: dict[str, Any], cron_schedule: str | None) -> dict[str, Any]:
    if "schedule" not in scheduling:
        flat = {key: scheduling.pop(key) for key in _FLAT_SCHEDULE_KEYS if key in scheduling}
        flat = {key: value for key, value in flat.items() if value is not None}
        if flat:
            scheduling["schedule"] = flat
    if "timerange" not in scheduling and "lookback" in scheduling:
        scheduling["timerange"] = {"lookback": scheduling.pop("lookback")}
    schedule = scheduling.get("schedule")
    if cron_schedule and (schedule is None or isinstance(schedule, dict)):
        schedule = dict(schedule or {})
        if not schedule.get("cron") and not schedule.get("frequency"):
            schedule["cron"] = cron_schedule
            scheduling["schedule"] = schedule
    return scheduling


def normalize_splunk_v2(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return *config* with splunk::2.x spellings moved to their v3 places.

    Idempotent, and leaves already-built nested models alone, so it is safe to
    run on raw YAML and again on the loader's partially parsed keyword
    arguments. The legacy ``search`` and ``cron_schedule`` keys are kept so an
    object round-trips unchanged.
    """
    normalized = deepcopy(dict(config))

    search = _text(normalized.get("search"))
    if search and not _text(normalized.get("query")):
        normalized["query"] = search

    cron_schedule = _text(normalized.get("cron_schedule"))
    scheduling = normalized.get("scheduling")
    if isinstance(scheduling, dict):
        normalized["scheduling"] = _normalise_scheduling(scheduling, cron_schedule)
    elif scheduling is None and cron_schedule:
        normalized["scheduling"] = {"schedule": {"cron": cron_schedule}}

    if normalized.get("trigger") is None:
        trigger: dict[str, Any] = {}
        if throttling := normalized.pop("throttling", None):
            trigger["throttling"] = throttling
        if (threshold := normalized.pop("threshold", None)) is not None:
            trigger["threshold"] = threshold
        if trigger:
            normalized["trigger"] = trigger
        else:
            normalized.pop("trigger", None)

    if normalized.get("actions") is None:
        actions = {
            key: value
            for key in ("notable", "risk", "email")
            if (value := normalized.pop(key, None))
        }
        if actions:
            normalized["actions"] = actions
        else:
            normalized.pop("actions", None)

    for block in ("scheduling", "trigger", "actions"):
        if normalized.get(block) == {}:
            del normalized[block]
    return normalized
