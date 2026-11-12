"""Compile an opentide rule's Graylog block into event-definition requests (graylog-1.0).

The author writes the query, the aggregation, the schedule, the event fields and
the notifications; this module derives the rest from the opentide rule: the
title, description, priority, tags and ATT&CK ids. Every request body is built
for the server version deploy read from ``GET /api/system`` (graylog-1.0,
Versions): a body never carries a property that version does not define, because
Graylog 6.3 accepts an unknown property on create and silently drops it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from opentide.models.platform import GraylogConfig
from opentide.models.platform_configs import GraylogEventLookup, GraylogEventTemplate
from opentide.models.rule import DetectionRule
from opentide.platforms.graylog.constraints import (
    PRIORITIES,
    as_list,
    duration_ms,
    parse_condition,
)

#: ``major.minor.patch`` of a Graylog server.
Version = tuple[int, int, int]

#: The oldest supported version: below it a tenant fails ``graylog_version_unsupported``.
MINIMUM_VERSION: Version = (6, 3, 0)
#: The first version of each line not affected by GHSA-j769-9gv9-65gr.
FIXED_VERSIONS: dict[tuple[int, int], Version] = {
    (6, 3): (6, 3, 12),
    (7, 0): (7, 0, 16),
    (7, 1): (7, 1, 12),
}
ADVISORY = "GHSA-j769-9gv9-65gr"
#: The version a dry run and ``validate`` build bodies for: no server is asked.
PREVIEW_VERSION: Version = (7, 2, 0)

DEFAULT_PRIORITY = 2
DEFAULT_EVERY = "5m"
DEFAULT_EVENT_LIMIT = 100
DEFAULT_TIMEZONE = "UTC"
MAX_TAGS = 64
MAX_TAG_LENGTH = 128
MAX_ATTACK_IDS = 64
ATTACK_FIELD = "attack_techniques"

DEFINITIONS_PATH = "/api/events/definitions"
VALIDATE_PATH = "/api/search/validate"

_VERSION = re.compile(r"\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")
_TAG_CHARACTER = re.compile(r"[^a-z0-9_.-]")


def parse_version(text: object) -> Version | None:
    """``(major, minor, patch)`` of a ``GET /api/system`` version (``6.3.5+eaa4b5d``).

    ``None`` when *text* is not one.
    """
    if not isinstance(text, str):
        return None
    match = _VERSION.match(text)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def version_text(version: Version) -> str:
    return ".".join(str(part) for part in version)


def is_vulnerable(version: Version) -> bool:
    """Whether *version* is affected by the access-token revocation flaw (GHSA-j769-9gv9-65gr)."""
    fixed = FIXED_VERSIONS.get(version[:2])
    return fixed is not None and version < fixed


class GraylogAliasError(ValueError):
    """A stream or notification alias the tenant does not define (``graylog_alias_unknown``).

    ``code``, ``reason`` and ``hint`` are what a deploy reports and a dry run's
    compile diagnostic reads.
    """

    code = "graylog_alias_unknown"

    def __init__(self, reason: str, *, tenant: str | None = None) -> None:
        self.tenant = tenant
        self.reason = f"tenant {tenant!r}: {reason}" if tenant else reason
        self.hint = (
            "add the alias to the tenant's stream_ids or notification_ids table, or change the "
            "block's streams or notifications"
        )
        super().__init__(f"{self.code}: {self.reason}")


@dataclass(frozen=True)
class CompiledDefinition:
    """What a block deploys on one tenant and one server version."""

    uuid: str
    title: str
    version: Version
    definition: dict[str, Any]
    #: ``(code, message)`` warnings the version or the block earns: a field the
    #: version cannot take, a priority it collapses.
    warnings: tuple[tuple[str, str], ...] = ()
    #: Aliases left out because no tenant resolved them (an offline preview).
    unresolved: dict[str, list[str]] = field(default_factory=dict)

    @property
    def config(self) -> dict[str, Any]:
        return self.definition["config"]

    @property
    def uuid_tag(self) -> str | None:
        """The ``opentide.<uuid>`` tag, when the version sends tags (7.2+)."""
        tag = f"opentide.{self.uuid}".lower()
        return tag if tag in self.definition.get("tags", []) else None


def block_of(rule: DetectionRule) -> GraylogConfig:
    """The rule's Graylog block, or an error naming the rule."""
    block = rule.platform_configs().graylog
    if block is None:
        raise ValueError(f"Rule {rule.metadata.uuid} ({rule.name}) has no graylog block")
    return block


# --- derived fields -------------------------------------------------------------------------


def attack_ids(rule: DetectionRule) -> list[str]:
    """The rule's Enterprise ATT&CK techniques by id, then their tactics in table order.

    Own techniques and those inherited through ``detection_model``, the set
    elastic-1.0 uses; at most :data:`MAX_ATTACK_IDS`.
    """
    from opentide.platforms.elastic.attack import (
        NON_ENTERPRISE_PREFIXES,
        TACTIC_MAP,
        TACTIC_ORDER,
        _cached_get_vocab_entry,
    )
    from opentide.platforms.sysdig.compile import rule_techniques

    techniques: list[str] = []
    stages: set[str] = set()
    for technique in rule_techniques(rule):
        entry = _cached_get_vocab_entry("att&ck", technique)
        if not entry or str(entry.get("name", "")).startswith(NON_ENTERPRISE_PREFIXES):
            continue
        techniques.append(technique)
        raw = _cached_get_vocab_entry("att&ck", technique, "tide.vocab.stages") or []
        for stage in [raw] if isinstance(raw, str) else raw:
            mapped = TACTIC_MAP.get(str(stage).strip().lower())
            if mapped is not None:
                stages.add(mapped[0])
    tactics = [tactic for stage, tactic in TACTIC_ORDER if stage in stages]
    return (sorted(set(techniques)) + tactics)[:MAX_ATTACK_IDS]


def derive_title(rule: DetectionRule, block: GraylogConfig) -> str:
    """The shared ``name``, else the opentide rule ``name``."""
    return block.name or rule.name


def derive_description(rule: DetectionRule, ids: Sequence[str], version: Version) -> str:
    """The rule description, whitespace collapsed; before 7.2, an ``ATT&CK:`` line after it."""
    text = " ".join(str(rule.description or "").split())
    if version < (7, 2, 0) and ids:
        text += "\n\nATT&CK: " + ", ".join(ids)
    return text


def priority_label(rule: DetectionRule, block: GraylogConfig) -> str | None:
    """The block ``priority``, else ``response.alert_severity``, else ``None``."""
    if block.priority:
        return block.priority
    response = rule.response
    if response is None or "alert_severity" not in response.model_fields_set:
        return None
    return str(response.alert_severity)


def derive_priority(label: str | None, version: Version) -> int:
    """Graylog's priority for *label*; ``Informational`` is 1 before 7.1."""
    by_name = {name.lower(): value for name, value in PRIORITIES.items()}
    value = by_name.get((label or "").strip().lower(), DEFAULT_PRIORITY)
    return 1 if value == 0 and version < (7, 1, 0) else value


def normalise_tag(tag: str) -> str:
    """Lower-cased, any character outside ``[a-z0-9_.-]`` as ``-``, cut at 128 characters."""
    return _TAG_CHARACTER.sub("-", tag.lower())[:MAX_TAG_LENGTH]


def derive_tags(
    rule: DetectionRule, block: GraylogConfig, tenant_tags: str | Sequence[str] | None
) -> list[str]:
    """Block tags, ``opentide``, ``opentide.<uuid>``, tenant tags; normalised, unique, ≤ 64."""
    candidates = [
        *as_list(block.tags),
        "opentide",
        f"opentide.{rule.metadata.uuid}",
        *as_list(tenant_tags),
    ]
    tags: list[str] = []
    for candidate in candidates:
        tag = normalise_tag(str(candidate))
        if tag and tag not in tags:
            tags.append(tag)
    return tags[:MAX_TAGS]


def _provider(value: object) -> dict[str, Any]:
    if isinstance(value, GraylogEventLookup):
        return {
            "type": "lookup-v1",
            "table_name": value.lookup.table,
            "key_field": value.lookup.key_field,
        }
    if isinstance(value, GraylogEventTemplate):
        template = value.template
    elif isinstance(value, str) and "${" not in value:
        template = "${source." + value + "}"
    else:
        template = str(value)
    return {"type": "template-v1", "template": template, "require_values": False}


def derive_field_spec(
    block: GraylogConfig, ids: Sequence[str], version: Version
) -> dict[str, dict[str, Any]]:
    """``event_fields`` by their value forms; before 7.2, plus ``attack_techniques``."""
    spec = {
        name: {"data_type": "string", "providers": [_provider(value)]}
        for name, value in (block.event_fields or {}).items()
    }
    if version < (7, 2, 0) and ids and ATTACK_FIELD not in spec:
        spec[ATTACK_FIELD] = {
            "data_type": "string",
            "providers": [
                {"type": "template-v1", "template": ",".join(ids), "require_values": False}
            ],
        }
    return spec


def window_ms(block: GraylogConfig) -> int:
    """The time range each run searches: ``window``, else ``every``, else 5 minutes."""
    schedule = block.schedule
    value = (schedule.window or schedule.every if schedule else None) or DEFAULT_EVERY
    return duration_ms(value)


def _resolve(
    aliases: Sequence[str], table: Mapping[str, str] | None, kind: str, tenant: str | None
) -> list[str]:
    known = dict(table or {})
    missing = [alias for alias in aliases if alias not in known]
    if missing:
        raise GraylogAliasError(
            f"{kind} alias(es) {', '.join(missing)} are not in the tenant's "
            f"{'stream_ids' if kind == 'stream' else 'notification_ids'} table",
            tenant=tenant,
        )
    return [known[alias] for alias in aliases]


def stream_aliases(block: GraylogConfig, setup: Any | None) -> list[str]:
    """The block's ``streams``, else the tenant's."""
    return as_list(block.streams) or as_list(getattr(setup, "streams", None))


def derive_config(
    block: GraylogConfig, setup: Any | None, *, tenant: str | None = None
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    """``config`` of the definition, and the aliases left unresolved without a tenant."""
    unresolved: dict[str, list[str]] = {}
    aliases = stream_aliases(block, setup)
    if setup is None:
        streams: list[str] = []
        if aliases:
            unresolved["streams"] = aliases
    else:
        streams = _resolve(aliases, setup.stream_ids, "stream", tenant)
    schedule = block.schedule
    cron = schedule.cron if schedule else None
    window = window_ms(block)
    every = window if cron else duration_ms((schedule.every if schedule else None) or DEFAULT_EVERY)
    config: dict[str, Any] = {
        "type": "aggregation-v1",
        "query": block.query,
        "query_parameters": [],
        "filters": [],
        "streams": streams,
        "stream_categories": as_list(block.stream_categories),
    }
    aggregation = block.aggregation
    if aggregation is not None:
        tree, series = parse_condition(aggregation.condition)
        config.update(
            group_by=as_list(aggregation.group_by),
            series=series,
            conditions={"expression": tree},
        )
    else:
        config.update(group_by=[], series=[], conditions={"expression": None})
    config.update(
        search_within_ms=window,
        execute_every_ms=every,
        use_cron_scheduling=bool(cron),
    )
    if cron and schedule is not None:
        config.update(
            cron_expression=cron,
            cron_timezone=schedule.timezone or DEFAULT_TIMEZONE,
        )
    if aggregation is None:
        config["event_limit"] = (
            block.event_limit if block.event_limit is not None else DEFAULT_EVENT_LIMIT
        )
    return config, unresolved


def compile_definition(
    rule: DetectionRule,
    version: Version,
    setup: Any | None = None,
    *,
    tenant: str | None = None,
) -> CompiledDefinition:
    """The event definition *rule* deploys on a server of *version*.

    *setup* is the tenant's ``[tenants.setup]``; without one (an offline
    preview), stream and notification aliases are left out and listed in
    :attr:`CompiledDefinition.unresolved`. Raises :class:`GraylogAliasError`
    for an alias the tenant does not define.
    """
    block = block_of(rule)
    ids = attack_ids(rule)
    warnings: list[tuple[str, str]] = []
    label = priority_label(rule, block)
    priority = derive_priority(label, version)
    if (label or "").strip().lower() == "informational" and priority != 0:
        warnings.append(
            (
                "graylog_priority_collapsed",
                f"Graylog {version_text(version)} has no Informational priority: sent as Low (1)",
            )
        )
    definition: dict[str, Any] = {
        "_scope": "DEFAULT",
        "title": derive_title(rule, block),
        "description": derive_description(rule, ids, version),
        "priority": priority,
        "alert": block.alert,
    }
    if block.remediation:
        definition["remediation_steps"] = block.remediation
    if block.summary:
        if version >= (7, 1, 0):
            definition["event_summary_template"] = block.summary
        else:
            warnings.append(
                (
                    "graylog_field_unsupported_version",
                    f"summary is left out: Graylog {version_text(version)} has no event summary "
                    "template (7.1 and later)",
                )
            )
    if version >= (7, 2, 0):
        definition["tags"] = derive_tags(rule, block, getattr(setup, "tags", None))
        definition["tactics_techniques"] = ids
    elif block.tags:
        warnings.append(
            (
                "graylog_field_unsupported_version",
                f"tags are left out: Graylog {version_text(version)} has no definition tags "
                "(7.2 and later)",
            )
        )
    config, unresolved = derive_config(block, setup, tenant=tenant)
    definition["config"] = config
    definition["field_spec"] = derive_field_spec(block, ids, version)
    definition["key_spec"] = as_list(block.event_key)
    definition["notification_settings"] = {
        "grace_period_ms": duration_ms(block.grace_period, allow_zero=True)
        if block.grace_period
        else 0,
        "backlog_size": block.backlog or 0,
    }
    notifications = as_list(block.notifications)
    if setup is None:
        notification_ids: list[str] = []
        if notifications:
            unresolved["notifications"] = notifications
    else:
        notification_ids = _resolve(notifications, setup.notification_ids, "notification", tenant)
    definition["notifications"] = [{"notification_id": value} for value in notification_ids]
    return CompiledDefinition(
        uuid=str(rule.metadata.uuid),
        title=definition["title"],
        version=version,
        definition=definition,
        warnings=tuple(warnings),
        unresolved=unresolved,
    )


# --- requests -------------------------------------------------------------------------------


def create_body(compiled: CompiledDefinition) -> dict[str, Any]:
    """6.3: the definition with ``share_request`` beside it; 7.x: ``{entity, share_request}``."""
    if compiled.version < (7, 0, 0):
        return {**compiled.definition, "share_request": None}
    return {"entity": compiled.definition, "share_request": None}


def update_body(compiled: CompiledDefinition, definition_id: str) -> dict[str, Any]:
    """The bare definition with its ``id``, on every version."""
    return {**compiled.definition, "id": definition_id}


def create_path() -> str:
    return f"{DEFINITIONS_PATH}?schedule=true"


def update_path(definition_id: str, *, enabled: bool) -> str:
    return f"{DEFINITIONS_PATH}/{definition_id}?schedule={'true' if enabled else 'false'}"


def delete_path(definition_id: str) -> str:
    return f"{DEFINITIONS_PATH}/{definition_id}"


def validate_body(compiled: CompiledDefinition) -> dict[str, Any]:
    """The ``POST /api/search/validate`` body for the definition's query, streams and window."""
    config = compiled.config
    return {
        "query": config["query"],
        "streams": list(config["streams"]),
        "stream_categories": list(config["stream_categories"]),
        "timerange": {"type": "relative", "range": config["search_within_ms"] // 1000},
    }


def api_request(method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
    """A request as the specification's goldens write it: ``{method, path, body}``."""
    return {"method": method, "path": path, "body": body}


def create_request(compiled: CompiledDefinition) -> dict[str, Any]:
    return api_request("POST", create_path(), create_body(compiled))


def update_request(
    compiled: CompiledDefinition, definition_id: str, *, enabled: bool = True
) -> dict[str, Any]:
    return api_request(
        "PUT", update_path(definition_id, enabled=enabled), update_body(compiled, definition_id)
    )
