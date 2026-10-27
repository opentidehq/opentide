"""Run an ES|QL, EQL, Lucene or KQL (kuery) query on an Elastic Security tenant.

ES|QL, EQL and Lucene run on Elasticsearch and return events. Kibana runs KQL
only inside detection rules, so a ``kuery`` query is previewed as a rule and
the rows are the alerts that preview raised.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar
from urllib.parse import quote

import requests

from opentide.core.time import format_utc_z
from opentide.models.system_config import ConfigurationModels, SystemConfig
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.query_text import mask_query
from opentide.query.models import (
    QueryColumn,
    QueryRefused,
    QueryRequest,
    QueryResult,
    TimeWindow,
    columns_of,
    flatten,
)
from opentide.query.runner import QueryRunner

#: Kibana caps the alerts one rule execution writes.
MAX_PREVIEW_ALERTS = 1000

_ESQL_LIMIT = re.compile(r"\|\s*limit\s+\d+", re.IGNORECASE)
#: Alert bookkeeping a preview adds to each event; the event's own fields are what was asked for.
_ALERT_PREFIXES = ("kibana.", "signal.")


class ElasticQueryRunner(QueryRunner):
    languages: ClassVar[tuple[str, ...]] = ("esql", "eql", "lucene", "kuery")

    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.platforms.transport import tenant_tls_verify

        if not isinstance(tenant, ConfigurationModels.Systems.Elastic.Tenant):
            raise TypeError(f"expected an Elastic tenant, got {type(tenant).__qualname__}")
        setup = tenant.setup
        reject_unsubstituted_placeholders(setup.api_key, client="Elastic")
        client = ElasticClient(
            url=setup.url,
            elasticsearch_url=setup.elasticsearch_url,
            api_key=setup.api_key,
            space=setup.space,
            verify_ssl=tenant_tls_verify(setup.ssl, platform="elastic", tenant=tenant.name),
            timeout=int(max(request.timeout, 1)),
        )
        language = request.language or self.languages[0]
        if language == "esql":
            return _esql(client, request, tenant.name)
        indices = _indices(client, request, tenant)
        if language == "eql":
            return _eql(client, request, indices, tenant.name)
        if language == "lucene":
            return _lucene(client, request, indices, tenant.name)
        return _kuery_preview(client, request, indices, tenant.name)


def esql_with_limit(query: str, limit: int) -> str:
    """*query* with ``| LIMIT limit+1`` appended, unless it already has a ``LIMIT``."""
    text = query.strip()
    if _ESQL_LIMIT.search(mask_query(text)):
        return text
    return f"{text}\n| LIMIT {limit + 1}"


def _range(window: TimeWindow) -> dict[str, Any]:
    return {
        "range": {
            "@timestamp": {
                "gte": format_utc_z(window.start),
                "lte": format_utc_z(window.end),
                "format": "strict_date_optional_time",
            }
        }
    }


def _esql(client: ElasticClient, request: QueryRequest, tenant: str) -> QueryResult:
    sent = esql_with_limit(request.text, request.limit)
    response = client.session.post(
        client._es_url("/_query"),
        json={"query": sent, "filter": _range(request.window)},
        timeout=client.timeout,
    )
    body = _body(response, tenant, "ES|QL")
    columns = tuple(
        QueryColumn(str(column.get("name")), column.get("type"))
        for column in body.get("columns", []) or []
        if isinstance(column, dict)
    )
    names = [column.name for column in columns]
    rows = [
        dict(zip(names, values, strict=False))
        for values in body.get("values", []) or []
        if isinstance(values, list)
    ]
    return QueryResult(
        columns=columns,
        rows=tuple(rows[: request.limit]),
        truncated=len(rows) > request.limit,
        partial=bool(body.get("is_partial")),
        sent=sent if sent != request.text.strip() else None,
        language="esql",
    )


def _eql(client: ElasticClient, request: QueryRequest, indices: str, tenant: str) -> QueryResult:
    response = client.session.post(
        client._es_url(f"/{quote(indices, safe=',*-_.')}/_eql/search"),
        json={"query": request.text, "size": request.limit + 1, "filter": _range(request.window)},
        timeout=client.timeout,
    )
    body = _body(response, tenant, "EQL")
    hits = body.get("hits", {}) if isinstance(body.get("hits"), dict) else {}
    events: list[dict[str, Any]] = list(hits.get("events", []) or [])
    for number, sequence in enumerate(hits.get("sequences", []) or [], start=1):
        for event in sequence.get("events", []) or []:
            events.append({**event, "_sequence": number})
    rows = [_event_row(event) for event in events if isinstance(event, dict)]
    return QueryResult(
        columns=columns_of(rows[: request.limit]),
        rows=tuple(rows[: request.limit]),
        truncated=len(rows) > request.limit or _total(hits) > request.limit,
        partial=bool(body.get("timed_out")),
        language="eql",
    )


def _lucene(client: ElasticClient, request: QueryRequest, indices: str, tenant: str) -> QueryResult:
    response = client.session.post(
        client._es_url(f"/{quote(indices, safe=',*-_.')}/_search"),
        json={
            "size": request.limit + 1,
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": request.text}}],
                    "filter": [_range(request.window)],
                }
            },
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        },
        timeout=client.timeout,
    )
    body = _body(response, tenant, "Lucene")
    hits = body.get("hits", {}) if isinstance(body.get("hits"), dict) else {}
    rows = [_event_row(hit) for hit in hits.get("hits", []) or [] if isinstance(hit, dict)]
    return QueryResult(
        columns=columns_of(rows[: request.limit]),
        rows=tuple(rows[: request.limit]),
        truncated=len(rows) > request.limit or _total(hits) > request.limit,
        partial=bool(body.get("timed_out")),
        language="lucene",
    )


def _kuery_preview(
    client: ElasticClient, request: QueryRequest, indices: str, tenant: str
) -> QueryResult:
    alerts = min(request.limit + 1, MAX_PREVIEW_ALERTS)
    seconds = request.window.seconds
    payload: dict[str, Any] = {
        "type": "query",
        "language": "kuery",
        "query": request.text,
        "name": "opentide query preview",
        "description": "Read-only preview run by opentide query",
        "risk_score": 21,
        "severity": "low",
        "interval": f"{seconds}s",
        "from": f"now-{seconds}s",
        "max_signals": alerts,
    }
    if request.data_view and not request.index:
        payload["data_view_id"] = request.data_view
    else:
        payload["index"] = indices.split(",")
    response = client.preview_rule(
        payload, invocation_count=1, timeframe_end=format_utc_z(request.window.end)
    )
    preview = _body(response, tenant, "KQL preview")
    errors = [
        str(error)
        for entry in preview.get("logs", []) or []
        if isinstance(entry, dict)
        for error in entry.get("errors", []) or []
    ]
    if errors:
        raise QueryRefused(f"Kibana refused the KQL query on {tenant}", detail="; ".join(errors))
    preview_id = str(preview.get("previewId") or "")
    if not preview_id:
        raise QueryRefused(f"Kibana returned no preview id on {tenant}")
    found = client.session.post(
        client._es_url(f"/.preview.alerts-security.alerts-{quote(client.space, safe='')}/_search"),
        json={
            "size": alerts,
            "query": {"term": {"kibana.alert.rule.uuid": preview_id}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        },
        timeout=client.timeout,
    )
    body = _body(found, tenant, "preview alerts")
    hits = body.get("hits", {}) if isinstance(body.get("hits"), dict) else {}
    rows = [
        {
            key: value
            for key, value in _event_row(hit).items()
            if not key.startswith(_ALERT_PREFIXES)
        }
        for hit in hits.get("hits", []) or []
        if isinstance(hit, dict)
    ]
    warnings = ["KQL runs only inside Kibana rules: the rows are the alerts a rule preview raised"]
    if request.limit + 1 > MAX_PREVIEW_ALERTS:
        warnings.append(f"a preview raises at most {MAX_PREVIEW_ALERTS} alerts")
    if preview.get("isAborted"):
        warnings.append("Kibana aborted the preview before it finished")
    return QueryResult(
        columns=columns_of(rows[: request.limit]),
        rows=tuple(rows[: request.limit]),
        truncated=len(rows) > request.limit or (len(rows) >= alerts and alerts < request.limit),
        partial=bool(preview.get("isAborted")),
        warnings=tuple(warnings),
        vendor_query_id=preview_id,
        language="kuery",
    )


def _indices(
    client: ElasticClient, request: QueryRequest, tenant: ConfigurationModels.Systems.Elastic.Tenant
) -> str:
    """The indices a query searches: ``--index``, the rule's data view or index, or the tenant's."""
    if request.index:
        return ",".join(request.index)
    if request.data_view:
        response = client.get_data_view_response(request.data_view)
        if response.status_code != 200:
            raise QueryRefused(
                f"cannot read data view {request.data_view!r} on {tenant.name} "
                f"(HTTP {response.status_code})"
            )
        body = response.json()
        view = (body.get("data_view") or body) if isinstance(body, dict) else {}
        title = view.get("title") if isinstance(view, dict) else None
        if title:
            return str(title)
    if tenant.setup.index:
        return ",".join(tenant.setup.index)
    raise QueryRefused(
        f"no index to search on {tenant.name}",
        detail="pass --index, or set index in the tenant's [tenants.setup]",
    )


def _event_row(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source")
    row = flatten(source) if isinstance(source, dict) else {}
    if hit.get("_index") is not None:
        row = {"_index": hit["_index"], **row}
    if "_sequence" in hit:
        row = {"_sequence": hit["_sequence"], **row}
    return row


def _total(hits: dict[str, Any]) -> int:
    total = hits.get("total")
    if isinstance(total, dict):
        total = total.get("value")
    return total if isinstance(total, int) else 0


def _body(response: requests.Response, tenant: str, what: str) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        body = None
    if response.status_code != 200:
        reason = None
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                root = (error.get("root_cause") or [{}])[0]
                reason = root.get("reason") if isinstance(root, dict) else None
                reason = reason or error.get("reason")
            elif error:
                reason = str(error)
            reason = reason or body.get("message")
        raise QueryRefused(
            f"Elastic refused the {what} query on {tenant} (HTTP {response.status_code})",
            detail=str(reason or response.text[:500] or "") or None,
        )
    return body if isinstance(body, dict) else {}


def declare() -> ElasticQueryRunner:
    return ElasticQueryRunner()
