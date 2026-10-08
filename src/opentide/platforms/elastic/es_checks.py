"""Elasticsearch pre-flight and mapping capability checks (RFC 0007 §6)."""

from __future__ import annotations

import re
from typing import Any

import structlog

from opentide.platforms.elastic.client import ElasticClient

logger = structlog.get_logger(__name__)

_FROM_PATTERN = re.compile(r"(?i)\bFROM\s+([^|]+)")


def run_esql_preflight(client: ElasticClient, query: str) -> list[dict[str, Any]]:
    """Execute ES|QL pre-flight query with LIMIT 0. Returns output columns."""
    preflight_query = query.rstrip() + "\n| LIMIT 0"
    resp = client.esql_query(preflight_query)
    if resp.status_code == 200:
        data = resp.json()
        return data.get("columns", [])

    # Check error response
    err_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    error = err_data.get("error", {})
    err_type = error.get("type") or ""
    reason = error.get("reason") or resp.text

    if err_type == "parsing_exception" or "parsing_exception" in str(error):
        raise ValueError(f"ES|QL parsing exception: {reason}")

    if err_type == "verification_exception" or "verification_exception" in str(error):
        # Extract sources from query
        match = _FROM_PATTERN.search(query)
        sources = match.group(1).strip() if match else ""
        if sources:
            # Check if sources resolve
            resolve_resp = client.resolve_index(sources)
            if resolve_resp.status_code == 200:
                resolve_data = resolve_resp.json()
                indices = resolve_data.get("indices", [])
                aliases = resolve_data.get("aliases", [])
                data_streams = resolve_data.get("data_streams", [])
                if not indices and not aliases and not data_streams:
                    logger.warning("esql_sources_not_onboarded_yet", sources=sources)
                    return []
        raise ValueError(f"ES|QL verification exception: {reason}")

    raise ValueError(f"ES|QL pre-flight failed (HTTP {resp.status_code}): {reason}")


def run_aggregation_fields_check(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
    esql_columns: list[dict[str, Any]] | None = None,
) -> None:
    """Verify that aggregation fields exist and are aggregatable via _field_caps or ES|QL columns."""
    rule_type = block.get("type", "query")

    # Collect fields to check
    fields: list[str] = []
    suppression = block.get("suppression") or {}
    if suppression.get("group_by"):
        fields.extend(suppression["group_by"])

    threshold = block.get("threshold") or {}
    if threshold.get("field"):
        if isinstance(threshold["field"], list):
            fields.extend(threshold["field"])
        else:
            fields.append(str(threshold["field"]))
    if threshold.get("cardinality") and isinstance(threshold["cardinality"], dict):
        if threshold["cardinality"].get("field"):
            fields.append(threshold["cardinality"]["field"])

    new_terms = block.get("new_terms") or {}
    if new_terms.get("fields"):
        fields.extend(new_terms["fields"])

    fields = list(dict.fromkeys(filter(None, fields)))
    if not fields:
        return

    # For ES|QL: group_by fields must be among pre-flight columns
    if rule_type == "esql":
        if suppression.get("group_by"):
            if esql_columns is not None:
                col_names = {c["name"] for c in esql_columns if isinstance(c, dict) and "name" in c}
                if not col_names:
                    # Sources not onboarded yet
                    return
                for g_field in suppression["group_by"]:
                    if g_field not in col_names:
                        raise ValueError(
                            f"ES|QL suppression group_by field '{g_field}' not in query columns: {sorted(col_names)}"
                        )
        return

    # Resolve index sources
    sources: str | None = None
    if block.get("data_view_id"):
        data_view = client.get_data_view(block["data_view_id"])
        if data_view:
            dv_obj = data_view.get("data_view") or data_view
            sources = dv_obj.get("title")
    elif block.get("index"):
        sources = ",".join(block["index"])
    elif setup_index:
        sources = ",".join(setup_index)
    else:
        logger.warning(
            "aggregation_field_check_skipped_no_source",
            reason="Rule has no explicit index, data_view_id, or tenant index",
        )
        return

    if not sources:
        return

    resp = client.field_caps(sources, fields)
    if resp.status_code != 200:
        logger.warning("field_caps_check_failed", status_code=resp.status_code, text=resp.text)
        return

    caps_data = resp.json()
    indices = caps_data.get("indices", [])
    if isinstance(indices, list) and not indices:
        logger.warning("sources_not_onboarded_yet", sources=sources)
        return

    fields_caps = caps_data.get("fields", {})
    for field_name in fields:
        if field_name not in fields_caps:
            raise ValueError(f"Field '{field_name}' not found in mappings for sources: {sources}")
        type_caps = fields_caps[field_name]
        is_aggregatable = any(
            isinstance(cap, dict) and cap.get("aggregatable") is True
            for cap in type_caps.values()
        )
        if not is_aggregatable:
            raise ValueError(f"Field '{field_name}' is not aggregatable in sources: {sources}")


def run_elasticsearch_checks(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
) -> None:
    """Run all mandatory Elasticsearch pre-flight checks before deploy or on live validation."""
    rule_type = block.get("type", "query")
    esql_columns: list[dict[str, Any]] | None = None

    if rule_type == "esql" and block.get("query"):
        esql_columns = run_esql_preflight(client, block["query"])

    run_aggregation_fields_check(
        client, block, setup_index=setup_index, esql_columns=esql_columns
    )
