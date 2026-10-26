"""Elasticsearch pre-flight and mapping capability checks (RFC 0007 §6)."""

from __future__ import annotations

from typing import Any

import requests

from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.query_text import esql_sources

_DATE_FIELD_TYPES = frozenset({"date", "date_nanos"})


class ElasticRuleCheckError(ValueError):
    """The rule itself failed an Elasticsearch check."""


class ElasticTenantError(RuntimeError):
    """The tenant cannot run the check (auth, or a missing preview privilege)."""


def esql_from_sources(query: str) -> str:
    """Index patterns named by the ``FROM`` or ``TS`` source command.

    ``FROM logs-* METADATA _id, _version | ...`` resolves as ``logs-*``.
    Sources may span lines; quotes are stripped, and comments and pipes or
    ``METADATA`` inside comments or strings are ignored.
    """
    return esql_sources(query)


def _error_payload(resp: requests.Response) -> tuple[str, str, str]:
    content_type = resp.headers.get("content-type", "")
    if not content_type.startswith("application/json"):
        return "", resp.text, resp.text
    try:
        err_data = resp.json()
    except ValueError:
        return "", resp.text, resp.text
    error = err_data.get("error", {}) if isinstance(err_data, dict) else {}
    if not isinstance(error, dict):
        return "", resp.text, resp.text
    err_type = str(error.get("type") or "")
    reason = str(error.get("reason") or resp.text)
    return err_type, reason, str(error)


def _raise_if_unauthorized(resp: requests.Response, action: str) -> None:
    if resp.status_code in (401, 403):
        raise ElasticTenantError(f"Elasticsearch {action} failed: HTTP {resp.status_code}")


def _note(warnings: list[str] | None, message: str) -> None:
    if warnings is not None:
        warnings.append(message)


def resolve_rule_sources(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
    warnings: list[str] | None = None,
) -> tuple[str | None, bool]:
    """Resolve index patterns for a rule block, checking ``data_view_id`` in Kibana when set.

    Returns ``(sources, has_explicit_source)``. A data view that is missing or
    unreadable (any non-200 other than 401/403) raises
    :class:`ElasticRuleCheckError`, which fails the rule; HTTP 401/403 raises
    :class:`ElasticTenantError`.
    """
    rule_type = block.get("type", "query")
    if rule_type == "machine_learning":
        return None, False
    if rule_type == "esql":
        sources = esql_from_sources(str(block.get("query") or ""))
        return (sources or None), bool(sources)

    data_view_id = block.get("data_view_id")
    if data_view_id:
        resp = client.get_data_view_response(str(data_view_id))
        if resp.status_code in (401, 403):
            raise ElasticTenantError(
                f"Kibana data_view '{data_view_id}' lookup failed: HTTP {resp.status_code}"
            )
        if resp.status_code != 200:
            # RFC 0007 §2: data_view_id names an existing data view, and this
            # platform never creates one. A data view is a Kibana object, not
            # data, so a missing one is an authoring error, not "not onboarded".
            raise ElasticRuleCheckError(
                f"Data view '{data_view_id}' lookup failed (HTTP {resp.status_code})"
            )
        data_view = resp.json()
        dv_obj = (data_view.get("data_view") or data_view) if isinstance(data_view, dict) else {}
        title = dv_obj.get("title") if isinstance(dv_obj, dict) else None
        return (str(title) if title else None), True

    if block.get("index"):
        return ",".join(block["index"]), True
    if setup_index:
        return ",".join(setup_index), True
    return None, False


def run_esql_preflight(
    client: ElasticClient,
    query: str,
    warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Execute an ES|QL pre-flight with ``LIMIT 0``. Returns output columns.

    Sources that resolve to nothing are a warning and yield an empty column
    list. A parse error, or a verification error whose sources do resolve,
    raises :class:`ElasticRuleCheckError`. HTTP 401 or 403 raises
    :class:`ElasticTenantError`.
    """
    preflight_query = query.rstrip() + "\n| LIMIT 0"
    resp = client.esql_query(preflight_query)
    _raise_if_unauthorized(resp, "_query")
    if resp.status_code == 200:
        data = resp.json()
        columns = data.get("columns", [])
        return columns if isinstance(columns, list) else []

    err_type, reason, blob = _error_payload(resp)

    if err_type == "parsing_exception" or "parsing_exception" in blob:
        raise ElasticRuleCheckError(f"ES|QL parsing exception: {reason}")

    if err_type == "verification_exception" or "verification_exception" in blob:
        sources = esql_from_sources(query)
        if sources:
            resolve_resp = client.resolve_index(sources)
            _raise_if_unauthorized(resolve_resp, "_resolve/index")
            if resolve_resp.status_code == 200:
                resolve_data = resolve_resp.json()
                indices = resolve_data.get("indices", [])
                aliases = resolve_data.get("aliases", [])
                data_streams = resolve_data.get("data_streams", [])
                if not indices and not aliases and not data_streams:
                    _note(warnings, f"ES|QL sources not onboarded yet: {sources}")
                    return []
        raise ElasticRuleCheckError(f"ES|QL verification exception: {reason}")

    raise ElasticRuleCheckError(f"ES|QL pre-flight failed (HTTP {resp.status_code}): {reason}")


def run_aggregation_fields_check(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
    esql_columns: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
    resolved_sources: tuple[str | None, bool] | None = None,
) -> None:
    """Verify aggregation fields exist and are aggregatable.

    ES|QL ``group_by`` must be among the pre-flight columns. Other rule types
    are checked with ``_field_caps``. A missing or non-aggregatable field
    raises :class:`ElasticRuleCheckError`. HTTP 401 or 403 raises
    :class:`ElasticTenantError`. Empty indices, and a rule with no source at
    all, are warnings.
    """
    rule_type = block.get("type", "query")

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
    cardinality = threshold.get("cardinality")
    if isinstance(cardinality, dict) and cardinality.get("field"):
        fields.append(cardinality["field"])

    new_terms = block.get("new_terms") or {}
    if new_terms.get("fields"):
        fields.extend(new_terms["fields"])

    fields = list(dict.fromkeys(filter(None, fields)))
    if not fields:
        return

    if rule_type == "esql":
        group_by = suppression.get("group_by") or []
        if group_by and esql_columns is not None:
            col_names = {c["name"] for c in esql_columns if isinstance(c, dict) and "name" in c}
            if not col_names:
                return
            for group_field in group_by:
                if group_field not in col_names:
                    names = ", ".join(sorted(col_names))
                    raise ElasticRuleCheckError(
                        f"ES|QL suppression group_by field '{group_field}' "
                        f"not in query columns: {names}"
                    )
        return

    if resolved_sources is None:
        sources, has_explicit = resolve_rule_sources(
            client, block, setup_index=setup_index, warnings=warnings
        )
    else:
        sources, has_explicit = resolved_sources

    if not has_explicit:
        _note(
            warnings,
            "aggregation field check skipped: rule has no explicit index, "
            "data_view_id, or tenant index",
        )
        return

    if not sources:
        return

    resp = client.field_caps(sources, fields)
    _raise_if_unauthorized(resp, "_field_caps")
    if resp.status_code != 200:
        # RFC 0007 §6: every field MUST be present and aggregatable; a check
        # that could not run is not a pass.
        raise ElasticRuleCheckError(
            f"Aggregation field check failed (HTTP {resp.status_code}): {resp.text}"
        )

    caps_data = resp.json()
    indices = caps_data.get("indices", [])
    if isinstance(indices, list) and not indices:
        _note(warnings, f"aggregation sources not onboarded yet: {sources}")
        return

    fields_caps = caps_data.get("fields", {})
    for field_name in fields:
        if field_name not in fields_caps:
            raise ElasticRuleCheckError(
                f"Field '{field_name}' not found in mappings for sources: {sources}"
            )
        type_caps = fields_caps[field_name]
        is_aggregatable = any(
            isinstance(cap, dict) and cap.get("aggregatable") is True for cap in type_caps.values()
        )
        if not is_aggregatable:
            raise ElasticRuleCheckError(
                f"Field '{field_name}' is not aggregatable in sources: {sources}"
            )


def run_timestamp_fields_check(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
    warnings: list[str] | None = None,
    resolved_sources: tuple[str | None, bool] | None = None,
) -> None:
    """Verify custom timestamp fields have ``date`` or ``date_nanos`` mappings in Elasticsearch.

    When indices or fields are not yet present in mappings, a warning is
    recorded so rules can be validated before data is onboarded. When a field
    is mapped as a non-date type (e.g. ``keyword`` or ``long``), raises
    :class:`ElasticRuleCheckError`.
    """
    overrides = block.get("overrides") or {}
    ts_override = overrides.get("timestamp") if isinstance(overrides, dict) else None
    eql = block.get("eql") or {}
    eql_ts = eql.get("timestamp_field") if isinstance(eql, dict) else None

    ts_fields = list(
        dict.fromkeys(
            str(field) for field in (ts_override, eql_ts) if field and str(field) != "@timestamp"
        )
    )
    if not ts_fields:
        return

    if resolved_sources is None:
        sources, _ = resolve_rule_sources(client, block, setup_index=setup_index, warnings=warnings)
    else:
        sources, _ = resolved_sources

    if not sources:
        return

    resp = client.field_caps(sources, ts_fields)
    _raise_if_unauthorized(resp, "_field_caps")
    if resp.status_code != 200:
        raise ElasticRuleCheckError(
            f"Timestamp field check failed (HTTP {resp.status_code}): {resp.text}"
        )

    caps_data = resp.json()
    indices = caps_data.get("indices", [])
    if isinstance(indices, list) and not indices:
        _note(warnings, f"timestamp sources not onboarded yet: {sources}")
        return

    fields_caps = caps_data.get("fields", {})
    for field_name in ts_fields:
        if field_name not in fields_caps:
            _note(
                warnings,
                f"Timestamp field '{field_name}' not found in mappings yet for sources: {sources}",
            )
            continue
        type_caps = fields_caps[field_name]
        is_date = isinstance(type_caps, dict) and any(
            field_type in _DATE_FIELD_TYPES
            or (isinstance(cap, dict) and cap.get("type") in _DATE_FIELD_TYPES)
            for field_type, cap in type_caps.items()
        )
        if not is_date:
            found = (
                ", ".join(sorted(type_caps.keys()))
                if isinstance(type_caps, dict) and type_caps
                else "unknown"
            )
            raise ElasticRuleCheckError(
                f"Timestamp field '{field_name}' is not a date/date_nanos field "
                f"(found: {found}) in sources: {sources}"
            )


def _check_searchable_fields(
    client: ElasticClient,
    sources: str,
    fields: list[str],
    label: str,
    warnings: list[str] | None,
) -> None:
    resp = client.field_caps(sources, fields)
    _raise_if_unauthorized(resp, "_field_caps")
    if resp.status_code != 200:
        raise ElasticRuleCheckError(
            f"{label} field check failed (HTTP {resp.status_code}): {resp.text}"
        )

    caps_data = resp.json()
    indices = caps_data.get("indices", [])
    if isinstance(indices, list) and not indices:
        _note(warnings, f"{label} sources not onboarded yet: {sources}")
        return

    fields_caps = caps_data.get("fields", {})
    for field_name in fields:
        if field_name not in fields_caps:
            _note(
                warnings,
                f"{label} field '{field_name}' not found in mappings yet for sources: {sources}",
            )
            continue
        type_caps = fields_caps[field_name]
        is_searchable = isinstance(type_caps, dict) and any(
            isinstance(cap, dict) and cap.get("searchable") is True for cap in type_caps.values()
        )
        if not is_searchable:
            raise ElasticRuleCheckError(
                f"{label} field '{field_name}' is not searchable in sources: {sources}"
            )


def run_threat_match_fields_check(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
    warnings: list[str] | None = None,
    resolved_sources: tuple[str | None, bool] | None = None,
) -> None:
    """Verify ``threat_match`` event and indicator mapping fields via ``_field_caps``.

    Missing indices or unmapped fields are recorded as warnings so rules can be
    validated before threat-intel feeds or event integrations are onboarded.
    Fields mapped with a non-searchable type raise :class:`ElasticRuleCheckError`.
    """
    if block.get("type") != "threat_match":
        return
    threat = block.get("threat")
    if not isinstance(threat, dict):
        return

    event_fields: list[str] = []
    indicator_fields: list[str] = []
    for group in threat.get("mapping") or []:
        if not isinstance(group, dict):
            continue
        for entry in group.get("entries") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("field"):
                event_fields.append(str(entry["field"]))
            if entry.get("value"):
                indicator_fields.append(str(entry["value"]))

    event_fields = list(dict.fromkeys(filter(None, event_fields)))
    indicator_fields = list(dict.fromkeys(filter(None, indicator_fields)))

    threat_indices = threat.get("index") or []
    threat_sources = (
        ",".join(str(idx) for idx in threat_indices if idx)
        if isinstance(threat_indices, list)
        else ""
    )
    if threat_sources and indicator_fields:
        _check_searchable_fields(
            client, threat_sources, indicator_fields, "Threat indicator", warnings
        )

    if event_fields:
        if resolved_sources is None:
            event_sources, _ = resolve_rule_sources(
                client, block, setup_index=setup_index, warnings=warnings
            )
        else:
            event_sources, _ = resolved_sources
        if event_sources:
            _check_searchable_fields(
                client, event_sources, event_fields, "Threat match event", warnings
            )


def run_elasticsearch_checks(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
) -> list[str]:
    """Run Elasticsearch pre-flight checks. Returns warnings; failures raise."""
    warnings: list[str] = []
    rule_type = block.get("type", "query")
    esql_columns: list[dict[str, Any]] | None = None

    if rule_type == "esql" and block.get("query"):
        esql_columns = run_esql_preflight(client, block["query"], warnings)

    resolved = resolve_rule_sources(
        client,
        block,
        setup_index=setup_index,
        warnings=warnings,
    )

    run_aggregation_fields_check(
        client,
        block,
        setup_index=setup_index,
        esql_columns=esql_columns,
        warnings=warnings,
        resolved_sources=resolved,
    )
    run_timestamp_fields_check(
        client,
        block,
        setup_index=setup_index,
        warnings=warnings,
        resolved_sources=resolved,
    )
    run_threat_match_fields_check(
        client,
        block,
        setup_index=setup_index,
        warnings=warnings,
        resolved_sources=resolved,
    )
    return warnings
