"""Compile OpenTide DetectionRule objects into Elastic Security Detection Engine format."""

from __future__ import annotations

import json
from typing import Any

from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.attack import resolve_elastic_threat

# Server-owned fields dropped when compiling or preparing for import
SERVER_OWNED_FIELDS = frozenset(
    {
        "id",
        "revision",
        "created_at",
        "created_by",
        "updated_at",
        "updated_by",
        "execution_summary",
        "immutable",
        "rule_source",
        "outcome",
        "related_integrations",
    }
)

SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

DEFAULT_RISK_SCORES = {
    "low": 21,
    "medium": 47,
    "high": 73,
    "critical": 99,
}

DEFAULT_BASELINE_VERSION = "8.14.0"


def _parse_version(version_str: str) -> tuple[int, ...]:
    parts = []
    for seg in version_str.split("."):
        clean = "".join(c for c in seg if c.isdigit())
        if clean:
            parts.append(int(clean))
        else:
            parts.append(0)
    return tuple(parts)


def check_version_compatibility(rule_dict: dict[str, Any], min_version_str: str) -> None:
    """Ensure rule fields are supported by the target Kibana baseline version."""
    target_version = _parse_version(min_version_str)

    if rule_dict.get("type") == "esql" and target_version < (8, 11, 0):
        raise ValueError(
            f"ES|QL rules require Kibana 8.11.0+, but tenant min_version is {min_version_str}"
        )
    if "alert_suppression" in rule_dict and target_version < (8, 6, 0):
        raise ValueError(
            f"alert_suppression requires Kibana 8.6.0+, but tenant min_version is {min_version_str}"
        )
    if "response_actions" in rule_dict and target_version < (8, 14, 0):
        raise ValueError(
            f"response_actions require Kibana 8.14.0+, but tenant min_version is {min_version_str}"
        )


def compile_rule(
    rule: DetectionRule,
    tenant_config: ConfigurationModels.Systems.ElasticSecurity.Tenant | None = None,
) -> dict[str, Any]:
    """Compile an OpenTide DetectionRule into an Elastic Security rule payload dictionary."""
    cfg = getattr(rule.configurations, "elastic_security", None) if rule.configurations else None
    if cfg is None:
        raise ValueError(f"Rule {rule.name} has no elastic_security configuration block")

    rule_type = cfg.type or "query"

    # Identity & metadata
    rule_id = cfg.rule_id or (rule.metadata.uuid if rule.metadata else "")
    if not rule_id:
        raise ValueError(f"Rule {rule.name} has neither rule_id nor metadata.uuid")

    name = cfg.name or rule.name
    description = rule.description or ""

    # Authors
    authors: list[str] = []
    if cfg.author:
        authors.extend(cfg.author)
    elif rule.metadata and rule.metadata.author:
        authors.append(rule.metadata.author)

    contributors = cfg.contributors or (rule.metadata.contributors if rule.metadata else None) or []
    for c in contributors:
        if c not in authors:
            authors.append(c)

    if not authors:
        authors = ["OpenTide"]

    # Severity & Risk score
    raw_severity = cfg.severity or (
        rule.response.alert_severity if rule.response and rule.response.alert_severity else "medium"
    )
    severity = SEVERITY_MAP.get(str(raw_severity).lower(), "medium")
    risk_score = (
        cfg.risk_score if cfg.risk_score is not None else DEFAULT_RISK_SCORES.get(severity, 47)
    )

    payload: dict[str, Any] = {
        "rule_id": rule_id,
        "name": name,
        "description": description,
        "type": rule_type,
        "author": authors,
        "severity": severity,
        "risk_score": risk_score,
        "from": cfg.query_from or "now-6m",
        "interval": cfg.interval or "5m",
        "to": cfg.to or "now",
    }

    # Enabled status
    if cfg.enabled is not None:
        payload["enabled"] = cfg.enabled

    # Query & language
    if rule_type != "machine_learning":
        if cfg.query is not None:
            payload["query"] = cfg.query
        if cfg.language:
            payload["language"] = cfg.language
        elif rule_type == "query":
            payload["language"] = "kuery"
        elif rule_type == "eql":
            payload["language"] = "eql"
        elif rule_type == "esql":
            payload["language"] = "esql"

    # Index / data_view_id
    if rule_type not in ("esql", "machine_learning"):
        if cfg.index is not None:
            payload["index"] = list(cfg.index)
        elif cfg.data_view_id is not None:
            payload["data_view_id"] = cfg.data_view_id

    # Investigation guide / note
    note = cfg.note
    if not note and rule.response and rule.response.procedure:
        proc = rule.response.procedure
        if isinstance(proc, str):
            note = proc
        elif hasattr(proc, "analysis") and proc.analysis:
            note = str(proc.analysis)
        elif hasattr(proc, "containment") and proc.containment:
            note = str(proc.containment)
        elif isinstance(proc, dict):
            note = str(proc.get("analysis") or proc.get("containment") or "")
        else:
            note = str(proc)
    if note:
        payload["note"] = note

    if cfg.setup:
        payload["setup"] = cfg.setup

    if cfg.tags:
        payload["tags"] = list(cfg.tags)
    elif rule.metadata and getattr(rule.metadata, "tags", None):
        payload["tags"] = list(rule.metadata.tags)

    if cfg.filters:
        payload["filters"] = list(cfg.filters)

    if cfg.max_signals is not None:
        payload["max_signals"] = cfg.max_signals

    if cfg.timestamp_override:
        payload["timestamp_override"] = cfg.timestamp_override
    if cfg.timestamp_override_fallback_disabled is not None:
        payload["timestamp_override_fallback_disabled"] = cfg.timestamp_override_fallback_disabled

    if cfg.building_block_type:
        payload["building_block_type"] = cfg.building_block_type

    # saved_query specific
    if rule_type == "saved_query" and cfg.saved_id:
        payload["saved_id"] = cfg.saved_id

    # Common fields (P1)
    if cfg.references:
        payload["references"] = list(cfg.references)
    if cfg.false_positives:
        payload["false_positives"] = list(cfg.false_positives)
    if cfg.risk_score_mapping:
        payload["risk_score_mapping"] = [
            m.model_dump(exclude_none=True) if hasattr(m, "model_dump") else m
            for m in cfg.risk_score_mapping
        ]
    if cfg.severity_mapping:
        payload["severity_mapping"] = [
            m.model_dump(exclude_none=True) if hasattr(m, "model_dump") else m
            for m in cfg.severity_mapping
        ]
    if cfg.rule_name_override:
        payload["rule_name_override"] = cfg.rule_name_override
    if cfg.investigation_fields:
        payload["investigation_fields"] = dict(cfg.investigation_fields)
    if cfg.required_fields:
        payload["required_fields"] = [
            m.model_dump(exclude_none=True) if hasattr(m, "model_dump") else m
            for m in cfg.required_fields
        ]
    if cfg.license:
        payload["license"] = cfg.license
    if cfg.output_index:
        payload["output_index"] = cfg.output_index
    if cfg.namespace:
        payload["namespace"] = cfg.namespace
    if cfg.version is not None:
        payload["version"] = cfg.version

    # EQL specific
    if rule_type == "eql":
        if cfg.timestamp_field:
            payload["timestamp_field"] = cfg.timestamp_field
        if cfg.event_category_override:
            payload["event_category_override"] = cfg.event_category_override
        if cfg.tiebreaker_field:
            payload["tiebreaker_field"] = cfg.tiebreaker_field

    # Threshold specific
    if rule_type == "threshold" and cfg.threshold:
        t_data: dict[str, Any] = {
            "field": (
                cfg.threshold.field
                if not isinstance(cfg.threshold.field, list)
                else list(cfg.threshold.field)
            ),
            "value": cfg.threshold.value,
        }
        if cfg.threshold.cardinality:
            t_data["cardinality"] = cfg.threshold.cardinality
        payload["threshold"] = t_data

    # Threat match specific
    if rule_type == "threat_match":
        if cfg.threat_index:
            payload["threat_index"] = list(cfg.threat_index)
        if cfg.threat_mapping:
            payload["threat_mapping"] = [
                m.model_dump(exclude_none=True) if hasattr(m, "model_dump") else m
                for m in cfg.threat_mapping
            ]
        if cfg.threat_query:
            payload["threat_query"] = cfg.threat_query
        if cfg.threat_language:
            payload["threat_language"] = cfg.threat_language
        if cfg.threat_indicator_path:
            payload["threat_indicator_path"] = cfg.threat_indicator_path
        if cfg.threat_filters:
            payload["threat_filters"] = list(cfg.threat_filters)
        if cfg.concurrent_searches is not None:
            payload["concurrent_searches"] = cfg.concurrent_searches
        if cfg.items_per_search is not None:
            payload["items_per_search"] = cfg.items_per_search

    # New terms specific
    if rule_type == "new_terms":
        if cfg.new_terms_fields:
            payload["new_terms_fields"] = list(cfg.new_terms_fields)
        if cfg.history_window_start:
            payload["history_window_start"] = cfg.history_window_start

    # Machine learning specific
    if rule_type == "machine_learning":
        if cfg.machine_learning_job_id:
            payload["machine_learning_job_id"] = (
                list(cfg.machine_learning_job_id)
                if isinstance(cfg.machine_learning_job_id, list)
                else cfg.machine_learning_job_id
            )
        if cfg.anomaly_threshold is not None:
            payload["anomaly_threshold"] = cfg.anomaly_threshold

    # Alert suppression
    if cfg.alert_suppression:
        payload["alert_suppression"] = (
            cfg.alert_suppression.model_dump(exclude_none=True)
            if hasattr(cfg.alert_suppression, "model_dump")
            else {k: v for k, v in dict(cfg.alert_suppression).items() if v is not None}
        )

    # MITRE ATT&CK threat mapping
    threats = resolve_elastic_threat(rule)
    if threats:
        payload["threat"] = threats

    # Exceptions list references
    if cfg.exceptions_list:
        payload["exceptions_list"] = [
            item.model_dump(exclude_none=True) if hasattr(item, "model_dump") else item
            for item in cfg.exceptions_list
        ]

    # Actions and response actions
    if cfg.actions:
        payload["actions"] = [
            action.model_dump(exclude_none=True) if hasattr(action, "model_dump") else action
            for action in cfg.actions
        ]

    if cfg.response_actions:
        payload["response_actions"] = [
            ra.model_dump(exclude_none=True) if hasattr(ra, "model_dump") else ra
            for ra in cfg.response_actions
        ]

    if cfg.meta:
        payload["meta"] = dict(cfg.meta)

    # Check version compatibility against tenant setup min_version
    min_version = (
        getattr(tenant_config.setup, "min_version", DEFAULT_BASELINE_VERSION)
        if tenant_config and hasattr(tenant_config, "setup")
        else DEFAULT_BASELINE_VERSION
    )
    check_version_compatibility(payload, min_version)

    # Filter out any server-owned fields that may have leaked
    return {k: v for k, v in payload.items() if k not in SERVER_OWNED_FIELDS}


def compile_rule_ndjson(
    rule: DetectionRule,
    tenant_config: ConfigurationModels.Systems.ElasticSecurity.Tenant | None = None,
) -> str:
    """Compile a DetectionRule into a single-line NDJSON JSON string."""
    data = compile_rule(rule, tenant_config=tenant_config)
    return json.dumps(data, sort_keys=True)
