"""Compile OpenTide DetectionRule objects into Elastic Security Detection Engine format."""

from __future__ import annotations

import copy
import json
from typing import Any

from opentide.deployment.utils import check_status
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.attack import resolve_elastic_threat
from opentide.platforms.elastic.durations import (
    date_math,
    duration_seconds,
    elastic_duration,
    format_duration,
)

SERVER_OWNED_FIELDS = frozenset(
    {
        "id",
        "version",
        "revision",
        "created_at",
        "created_by",
        "updated_at",
        "updated_by",
        "execution_summary",
        "immutable",
        "rule_source",
        "outcome",
    }
)

SEVERITY_TABLE: dict[str, tuple[str, int]] = {
    "Informational": ("low", 1),
    "Low": ("low", 21),
    "Medium": ("medium", 47),
    "High": ("high", 73),
    "Critical": ("critical", 99),
}

# Normalization mapping for lowercase / case-insensitive severity lookups
SEVERITY_NORM = {k.lower(): k for k in SEVERITY_TABLE}


def compile_response(action: dict[str, Any]) -> dict[str, Any]:
    """Compile author response action into Kibana detection engine response_action."""
    if "endpoint" in action:
        params: dict[str, Any] = {"command": action["endpoint"]}
        if action.get("comment"):
            params["comment"] = action["comment"]
        if action.get("field"):
            params["config"] = {"field": action["field"], "overwrite": False}
        return {"action_type_id": ".endpoint", "params": params}
    if "osquery" in action:
        return {"action_type_id": ".osquery", "params": copy.deepcopy(action["osquery"])}
    return copy.deepcopy(action)


def compile_filter(entry: dict[str, Any]) -> dict[str, Any]:
    """Compile filter entry: phrase shorthand becomes detection engine phrase filter."""
    if "field" in entry and "value" in entry and "meta" not in entry and "query" not in entry:
        field, value = entry["field"], entry["value"]
        return {
            "meta": {
                "key": field,
                "negate": bool(entry.get("negate", False)),
                "disabled": False,
                "type": "phrase",
                "params": {"query": value},
            },
            "query": {"match_phrase": {field: value}},
        }
    return copy.deepcopy(entry)


def related_integration(entry: str | dict[str, Any]) -> dict[str, str]:
    """Compile integration block: string 'pkg' becomes {'package': pkg, 'version': '*'}; dict keeps version default."""
    item = {"package": entry} if isinstance(entry, str) else dict(entry)
    item.setdefault("version", "*")
    return item


def _alert_level(block: dict[str, Any], response: dict[str, Any]) -> str:
    severity = block.get("severity")
    if isinstance(severity, dict):
        raw = severity.get("default") or response.get("alert_severity") or "Informational"
    elif isinstance(severity, str):
        raw = severity
    else:
        raw = response.get("alert_severity") or "Informational"
    return SEVERITY_NORM.get(raw.strip().lower(), "Informational")


def compile_rule(
    rule: DetectionRule | dict[str, Any],
    tenant_config: ConfigurationModels.Systems.Elastic.Tenant | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile an OpenTide rule into an Elastic Security detection engine rule body."""
    # Convert DetectionRule to dictionary representation if needed
    if isinstance(rule, DetectionRule):
        raw_rule = rule.model_dump(by_alias=True, exclude_none=False)
        rule_obj = rule
    else:
        raw_rule = rule
        from opentide.loading.rule_loader import load_rule_from_dict

        rule_obj = load_rule_from_dict(raw_rule)

    configurations = raw_rule.get("configurations") or {}
    block = copy.deepcopy(configurations.get("elastic") or {})
    rule_type = block.get("type", "query")
    response = raw_rule.get("response") or {}

    setup: dict[str, Any] = {}
    if tenant_config is not None:
        if hasattr(tenant_config, "setup"):
            setup_obj = tenant_config.setup
            setup = {
                "url": getattr(setup_obj, "url", ""),
                "elasticsearch_url": getattr(setup_obj, "elasticsearch_url", ""),
                "space": getattr(setup_obj, "space", "default"),
                "index": getattr(setup_obj, "index", None),
                "tags": getattr(setup_obj, "tags", None),
                "suppression": getattr(setup_obj, "suppression", True),
            }
        elif isinstance(tenant_config, dict):
            setup = tenant_config.get("setup", tenant_config)

    # Status & enabled
    status = block.get("status") or "STAGING"
    strategy = check_status(status)
    enabled = strategy != StatusStrategy.DISABLEMENT

    # Severity & Risk score
    level = _alert_level(block, response)
    severity, default_risk = SEVERITY_TABLE[level]
    risk_score = default_risk

    risk = block.get("risk")
    if isinstance(risk, int):
        risk_score = risk
    elif isinstance(risk, dict) and risk.get("score") is not None:
        risk_score = risk["score"]

    scheduling = block.get("scheduling") or {}
    interval = scheduling.get("interval", "5m")
    lookback = scheduling.get("lookback", "1m")
    window = format_duration(
        duration_seconds(interval) + duration_seconds(lookback, allow_zero=True)
    )

    metadata = raw_rule.get("metadata") or {}
    rule_id = metadata.get("uuid") or (rule_obj.metadata.uuid if rule_obj.metadata else "")
    rule_name = block.get("name") or raw_rule.get("name") or ""
    description = raw_rule.get("description") or ""

    body: dict[str, Any] = {
        "rule_id": rule_id,
        "type": rule_type,
        "name": rule_name,
        "description": description.rstrip(),
        "enabled": enabled,
        "severity": severity,
        "risk_score": risk_score,
        "interval": date_math(interval),
        "from": "now-" + window,
        "to": "now",
    }

    # Language
    if rule_type == "eql":
        body["language"] = "eql"
    elif rule_type == "esql":
        body["language"] = "esql"
    elif rule_type != "machine_learning":
        body["language"] = block.get("language") or "kuery"

    # Query
    if block.get("query") is not None:
        body["query"] = block["query"].rstrip()

    # Index or data_view_id
    if block.get("data_view_id"):
        body["data_view_id"] = block["data_view_id"]
    elif rule_type not in ("esql", "machine_learning"):
        index = block.get("index") or setup.get("index")
        if isinstance(index, list) and index:
            body["index"] = list(index)

    # Filters
    if block.get("filters") is not None and rule_type not in ("esql", "machine_learning"):
        body["filters"] = [compile_filter(entry) for entry in block["filters"]]

    # Type-specific objects
    if (threshold := block.get("threshold")) is not None:
        body["threshold"] = {
            "field": list(threshold.get("field") or []),
            "value": threshold["value"],
        }
        if threshold.get("cardinality"):
            body["threshold"]["cardinality"] = [threshold["cardinality"]]

    if (new_terms := block.get("new_terms")) is not None:
        body["new_terms_fields"] = list(new_terms["fields"])
        body["history_window_start"] = "now-" + date_math(new_terms["history_window_start"])

    for key in ("timestamp_field", "event_category_override", "tiebreaker_field"):
        if (block.get("eql") or {}).get(key) is not None:
            body[key] = block["eql"][key]

    if (threat_match := block.get("threat")) is not None:
        body["threat_index"] = list(threat_match["index"])
        body["threat_query"] = threat_match["query"]
        if threat_match.get("language"):
            body["threat_language"] = threat_match["language"]
        if threat_match.get("filters") is not None:
            body["threat_filters"] = [compile_filter(entry) for entry in threat_match["filters"]]
        if threat_match.get("indicator_path") is not None:
            body["threat_indicator_path"] = threat_match["indicator_path"]
        body["threat_mapping"] = [
            {
                "entries": [
                    {"type": entry.get("type", "mapping"), **entry}
                    for entry in group["entries"]
                ]
            }
            for group in threat_match["mapping"]
        ]

    if (ml := block.get("machine_learning")) is not None:
        body["machine_learning_job_id"] = copy.deepcopy(ml["job_id"])
        body["anomaly_threshold"] = ml["anomaly_threshold"]

    # Severity & Risk mappings
    severity_mapping = (
        block["severity"]["mapping"] if isinstance(block.get("severity"), dict) else None
    )
    if severity_mapping:
        body["severity_mapping"] = [
            {"operator": "equals", **entry} if "operator" not in entry else dict(entry)
            for entry in severity_mapping
        ]

    if isinstance(risk, dict) and risk.get("mapping"):
        body["risk_score_mapping"] = [
            {"operator": "equals", **entry} if "operator" not in entry else dict(entry)
            for entry in risk["mapping"]
        ]

    # Overrides
    overrides = block.get("overrides") or {}
    if overrides.get("name") is not None:
        body["rule_name_override"] = overrides["name"]
    if overrides.get("timestamp") is not None:
        body["timestamp_override"] = overrides["timestamp"]
    if "disable_fallback" in overrides and overrides.get("disable_fallback") is not None:
        body["timestamp_override_fallback_disabled"] = overrides["disable_fallback"]

    # Actions
    actions = block.get("actions") or {}
    if isinstance(actions, dict):
        if actions.get("notify") is not None:
            body["actions"] = copy.deepcopy(actions["notify"])
        if actions.get("respond") is not None:
            body["response_actions"] = [compile_response(item) for item in actions["respond"]]
        timeline = actions.get("timeline") or {}
        if timeline.get("id") is not None:
            body["timeline_id"] = timeline["id"]
        if timeline.get("title") is not None:
            body["timeline_title"] = timeline["title"]

    if scheduling.get("max_alerts") is not None:
        body["max_signals"] = scheduling["max_alerts"]

    # Alert suppression
    suppression = block.get("suppression")
    if suppression is not None and setup.get("suppression", True):
        compiled_suppression: dict[str, Any] = {}
        if rule_type != "threshold":
            compiled_suppression["group_by"] = list(suppression["group_by"])
        if suppression.get("duration"):
            amount, unit = elastic_duration(suppression["duration"], "hms")
            compiled_suppression["duration"] = {"value": amount, "unit": unit}
        if rule_type != "threshold":
            compiled_suppression["missing_fields_strategy"] = suppression.get(
                "missing_fields_strategy", "suppress"
            )
        body["alert_suppression"] = compiled_suppression

    # Highlighted / investigation fields
    if block.get("highlighted_fields"):
        body["investigation_fields"] = {"field_names": list(block["highlighted_fields"])}

    # Required fields
    if block.get("required_fields"):
        body["required_fields"] = sorted(
            [{"name": f["name"], "type": f["type"]} for f in block["required_fields"]],
            key=lambda f: f["name"],
        )

    # Integrations
    if block.get("integration"):
        body["related_integrations"] = [related_integration(e) for e in block["integration"]]

    # Setup guide
    guide = block.get("guide") or {}
    if guide.get("setup"):
        body["setup"] = guide["setup"].rstrip()

    # False positives
    if block.get("false_positives"):
        body["false_positives"] = copy.deepcopy(block["false_positives"])

    # Building block
    if block.get("building_block"):
        body["building_block_type"] = "default"

    # Exceptions
    exceptions = block.get("exceptions")
    if exceptions is not None:
        lists = copy.deepcopy(exceptions.get("lists") or [])
        endpoint_entry = {
            "id": "endpoint_list",
            "list_id": "endpoint_list",
            "namespace_type": "agnostic",
            "type": "endpoint",
        }
        if exceptions.get("endpoint") and endpoint_entry not in lists:
            lists.append(endpoint_entry)
        if lists:
            body["exceptions_list"] = lists

    # Tags: "OpenTide" first, then tenant tags, then block tags, de-duplicated
    tenant_tags = list(setup.get("tags") or [])
    block_tags = list(block.get("tags") or [])
    body["tags"] = list(dict.fromkeys(["OpenTide", *tenant_tags, *block_tags]))

    # Author
    author_list = filter(
        None, [metadata.get("author"), *(metadata.get("contributors") or [])]
    )
    authors = list(dict.fromkeys(author_list))
    if authors:
        body["author"] = authors

    # References (public references in ascending integer key order)
    references = raw_rule.get("references") or {}
    public = references.get("public") if isinstance(references, dict) else None
    if public and isinstance(public, dict):
        try:
            sorted_keys = sorted(public, key=int)
            body["references"] = [public[k] for k in sorted_keys]
        except (ValueError, TypeError):
            body["references"] = [public[k] for k in sorted(public)]

    # Investigation guide / note
    proc = response.get("procedure") if isinstance(response, dict) else None
    proc_analysis = (
        proc.get("analysis") if isinstance(proc, dict) else getattr(proc, "analysis", None)
    )
    note = (guide.get("investigation") if isinstance(guide, dict) else None) or proc_analysis
    if note:
        body["note"] = str(note).rstrip()

    # MITRE ATT&CK threat
    threat = resolve_elastic_threat(rule_obj)
    if threat:
        body["threat"] = threat

    # Ensure server-owned fields never leak
    return {k: v for k, v in body.items() if k not in SERVER_OWNED_FIELDS}


def compile_rule_ndjson(
    rule: DetectionRule | dict[str, Any],
    tenant_config: ConfigurationModels.Systems.Elastic.Tenant | dict[str, Any] | None = None,
) -> str:
    """Compile a DetectionRule into a single-line NDJSON JSON string."""
    data = compile_rule(rule, tenant_config=tenant_config)
    return json.dumps(data, sort_keys=True)
