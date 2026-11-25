"""The Python Elastic Security client, driven through each scenario (UC-4.2).

``cargo xtask cassettes record elastic/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (each rule's block and compiled payload, the queries) for
the Rust connector's tests (``crates/opentide-connectors/tests/elastic.rs``), which
must send what this sent, byte for byte.

Scenarios:

- ``deploy``: ``ElasticDeploy.deploy_mdr`` over one batch: a rule created (404 first),
  one updated with the remote's fields preserved, one whose type changes (deleted,
  then created), a prebuilt rule left alone, a deletion of a rule that is not there,
  a disabled rule, an ES|QL rule (its pre-flight), a threshold rule (its fields'
  capabilities), a rule naming a data view that is not there, then a rule the key
  may not read (401), which ends the batch.
- ``query``: ``opentide query``'s runner: ES|QL (one row past the limit, then an
  unknown index), Lucene on the tenant's index, an EQL sequence, KQL through a rule
  preview (on the tenant's index, then on a data view), Lucene on a data view, a
  gateway's page, a KQL query Kibana refuses.
- ``validate``: ``validate query --live``'s check of each rule: its Elasticsearch
  checks and a preview of the rule deploy would create, ending at a fixed time.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels as C
from opentide.platforms.elastic import validator as elastic_validator
from opentide.platforms.elastic.compile import compile_rule
from opentide.platforms.elastic.deployer import ElasticDeploy
from opentide.platforms.elastic.es_checks import ElasticRuleCheckError, ElasticTenantError
from opentide.platforms.elastic.runner import ElasticQueryRunner
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow

UUID = "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c00"
WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
NOW = datetime(2026, 10, 27, 8, 0, 0, 250000, tzinfo=timezone.utc)

QUERIES: list[dict[str, Any]] = [
    {"text": "FROM logs-* // no LIMIT here", "language": "esql", "limit": 1},
    {"text": "FROM nope", "language": "esql", "limit": 100},
    {"text": "process.name:cmd.exe", "language": "lucene", "limit": 100},
    {
        "text": "sequence [process where true] [process where true]",
        "language": "eql",
        "limit": 100,
        "index": ["logs-*"],
    },
    {"text": 'process.name: "powershell.exe"', "language": "kuery", "limit": 100},
    {"text": "process.name: cmd.exe", "language": "kuery", "limit": 5, "data_view": "dv-logs"},
    {"text": "process.name:cmd.exe", "language": "lucene", "limit": 1, "data_view": "dv-logs"},
    {"text": "*", "language": "lucene", "limit": 100, "index": ["broken-*"]},
    {"text": "a::b", "language": "kuery", "limit": 100},
]


def _tenant() -> Any:
    setup = C.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.elastic.invalid",
        elasticsearch_url="https://es.elastic.invalid",
        api_key=os.environ.get("ELASTIC_API_KEY", "fixture"),
        space="soc",
        index=["logs-*", "winlogbeat-*"],
    )
    return C.Systems.Elastic.Tenant(name="soc", description="", setup=setup)


def _rule(suffix: str, status: str, block: dict[str, Any], name: str = "") -> Any:
    raw = {
        "name": name or f"Elastic rule {suffix}",
        "metadata": {
            "uuid": f"{UUID}{suffix}",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
            "author": "Detection Engineering",
        },
        "description": f"Rule {suffix} of the Elastic connector's cassettes.",
        "techniques": [],
        "response": {"alert_severity": "High"},
        "configurations": {
            "elastic": {
                "enabled": True,
                "schema": "platform::elastic::1.0",
                "status": status,
                **block,
            }
        },
    }
    return load_rule_from_dict(raw)


def _query(query: str, **extra: Any) -> dict[str, Any]:
    return {"type": "query", "language": "kuery", "query": query, **extra}


def deploy_rules() -> list[Any]:
    return [
        _rule("01", "STAGING", _query('process.name: "cmd.exe"', index=["logs-*"])),
        _rule("02", "PRODUCTION", _query("process.name: *", index=["logs-*"])),
        _rule(
            "03",
            "STAGING",
            {
                "type": "eql",
                "query": 'process where process.name == "cmd.exe"',
                "index": ["logs-*"],
            },
        ),
        _rule("04", "STAGING", _query("event.kind: alert", index=["logs-*"])),
        _rule("05", "REMOVED", _query("event.kind: alert", index=["logs-*"])),
        _rule("06", "DISABLED", _query("event.kind: alert", index=["logs-*"])),
        _rule(
            "07",
            "STAGING",
            {
                "type": "esql",
                "query": "FROM logs-* METADATA _id\n| STATS c = COUNT(*) BY host.name, user.name",
                "suppression": {"group_by": ["host.name"]},
            },
            name="Élastic ES|QL — grouped",
        ),
        _rule(
            "08",
            "STAGING",
            {
                "type": "threshold",
                "language": "lucene",
                "query": 'event.code:"4625"',
                "index": ["logs-system.security-*"],
                "threshold": {
                    "field": ["user.name"],
                    "value": 50,
                    "cardinality": {"field": "source.ip", "value": 8},
                },
                "overrides": {"timestamp": "event.created"},
            },
        ),
        _rule("09", "STAGING", _query("event.kind: alert", data_view_id="dv-missing")),
        _rule("0a", "STAGING", _query("event.kind: alert", index=["logs-*"])),
    ]


def validate_rules() -> list[Any]:
    return [
        _rule("11", "STAGING", _query('process.name: "powershell.exe"', index=["logs-*"])),
        _rule(
            "12",
            "STAGING",
            {
                "type": "esql",
                "query": 'FROM missing-* METADATA _id\n| WHERE process.name == "cmd.exe"',
            },
        ),
        _rule(
            "13",
            "STAGING",
            {"type": "esql", "query": "FROM logs-* | parse error"},
        ),
        _rule("14", "STAGING", _query("a::b", index=["logs-*"])),
        _rule("15", "STAGING", _query("bad-schema: x", data_view_id="dv-logs")),
        _rule(
            "16",
            "STAGING",
            {
                "type": "threshold",
                "language": "kuery",
                "query": "event.code: 4625",
                "index": ["logs-*"],
                "threshold": {"field": ["message"], "value": 5},
            },
        ),
    ]


def deploy() -> None:
    tenant = _tenant()
    runner = ElasticQueryRunner()
    client = runner.elastic_client(tenant, timeout=30)
    with contextlib.suppress(ElasticTenantError):
        ElasticDeploy().deploy_mdr(SimpleNamespace(rules=deploy_rules()), client, tenant)


def query() -> None:
    tenant = _tenant()
    runner = ElasticQueryRunner()
    for item in QUERIES:
        request = QueryRequest(
            platform="elastic",
            text=item["text"],
            window=WINDOW,
            limit=item["limit"],
            language=item["language"],
            index=tuple(item.get("index", ())),
            data_view=item.get("data_view"),
        )
        with contextlib.suppress(QueryRefused):
            runner.run(request, tenant)


def validate() -> None:
    elastic_validator.utc_now = lambda: NOW
    tenant = _tenant()
    check = elastic_validator.ElasticValidator()
    client = check.elastic.elastic_client(tenant, timeout=10)
    for rule in validate_rules():
        with contextlib.suppress(ElasticRuleCheckError, ElasticTenantError):
            check._validate_rule(rule, client, tenant, [])


def _rule_input(rule: Any, tenant: Any) -> dict[str, Any]:
    cfg = rule.configurations.elastic
    return {
        "rule_id": str(rule.metadata.uuid),
        "name": rule.name,
        "status": cfg.status,
        "block": cfg.model_dump(by_alias=True, exclude_none=False, mode="json"),
        "payload": compile_rule(rule, tenant_config=tenant),
    }


def fixture(path: str) -> None:
    tenant = _tenant()
    document = {
        "deploy": [_rule_input(rule, tenant) for rule in deploy_rules()],
        "validate": [_rule_input(rule, tenant) for rule in validate_rules()],
        "query": {
            "window": [WINDOW.start.isoformat(), WINDOW.end.isoformat()],
            "queries": QUERIES,
        },
        "now": NOW.isoformat(),
    }
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        json.dump(document, out, indent=2)
        out.write("\n")


def main() -> int:
    scenario = sys.argv[1]
    if scenario == "fixture":
        fixture(sys.argv[2])
    else:
        {"deploy": deploy, "query": query, "validate": validate}[scenario]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
