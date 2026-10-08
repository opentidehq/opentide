"""Export detection rules from Elastic Security and convert to OpenTide detection rules (RFC 0007)."""

from __future__ import annotations

import copy
import re
import uuid
from pathlib import Path
from typing import Any

import yaml

# Standard namespace UUID for deriving unique rule UUIDs when converting prebuilt to custom rules
OPENTIDE_MIGRATION_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


class IndentedYamlDumper(yaml.SafeDumper):
    """YAML dumper preserving list indents and formatting."""

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, False)


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


IndentedYamlDumper.add_representer(str, _represent_str)


def sanitize_filename(name: str) -> str:
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join(" " if c in invalid_chars else c for c in name)
    return " ".join(sanitized.split())


def extract_techniques(threats: list[dict[str, Any]] | None) -> list[str]:
    """Extract ATT&CK technique IDs from Kibana threat array."""
    if not threats:
        return []
    techniques: list[str] = []
    for threat in threats:
        for tech in threat.get("technique", []):
            subtechniques = tech.get("subtechnique", [])
            if subtechniques:
                for sub in subtechniques:
                    if sub_id := sub.get("id"):
                        techniques.append(sub_id)
            elif tech_id := tech.get("id"):
                techniques.append(tech_id)
    return list(dict.fromkeys(techniques))


def _clean_empty(d: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, dict):
            sub = _clean_empty(v)
            if sub:
                out[k] = sub
        elif isinstance(v, list):
            if v:
                out[k] = v
        else:
            out[k] = v
    return out


def kibana_to_opentide(
    rule: dict[str, Any],
    make_custom: bool = True,
    uuid_override: str | None = None,
    name_suffix: str = " (Custom)",
) -> dict[str, Any]:
    """Convert an exported Kibana detection engine rule dict into OpenTide DetectionRule dict."""
    rule_type = rule.get("type", "query")

    raw_rule_id = rule.get("rule_id") or rule.get("id") or ""
    if uuid_override:
        rule_id = uuid_override
    elif make_custom and (rule.get("immutable") or rule.get("rule_source", {}).get("type") == "external"):
        rule_id = str(uuid.uuid5(OPENTIDE_MIGRATION_NS, raw_rule_id))
    else:
        rule_id = raw_rule_id

    rule_name = str(rule.get("name", "Unnamed Rule"))
    if make_custom and name_suffix and (rule.get("immutable") or rule.get("rule_source", {}).get("type") == "external"):
        rule_name = f"{rule_name}{name_suffix}"
    description = str(rule.get("description", "")).strip()

    authors = rule.get("author", [])
    if isinstance(authors, list) and authors:
        author = str(authors[0])
        contributors = [str(a) for a in authors[1:]]
    elif isinstance(authors, str):
        author = authors
        contributors = []
    else:
        author = "Elastic Security"
        contributors = []

    created = str(rule.get("created_at", "")).split("T")[0] or "2026-01-01"
    modified = str(rule.get("updated_at", "")).split("T")[0] or created

    techniques = extract_techniques(rule.get("threat"))

    kibana_sev = str(rule.get("severity", "medium")).lower()
    sev_map = {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }
    alert_severity = sev_map.get(kibana_sev, "Medium")

    status = "PRODUCTION" if rule.get("enabled", False) else "STAGING"

    elastic_block: dict[str, Any] = {
        "enabled": True,
        "schema": "platform::elastic::1.0",
        "status": status,
        "type": rule_type,
    }

    # Query & language
    if rule_type in ("query", "eql", "esql", "threshold", "new_terms", "threat_match"):
        if rule.get("query"):
            elastic_block["query"] = rule["query"].strip()
        lang = rule.get("language")
        if rule_type in ("query", "threshold", "new_terms", "threat_match") and lang in ("kuery", "lucene"):
            elastic_block["language"] = lang

    # Index
    if rule_type not in ("esql", "machine_learning"):
        if rule.get("data_view_id"):
            elastic_block["data_view_id"] = rule["data_view_id"]
        elif rule.get("index"):
            elastic_block["index"] = list(rule["index"])

    # Scheduling
    interval = rule.get("interval", "5m")
    # from is now-<sum>, e.g. now-6m
    from_val = rule.get("from", "now-6m")
    lookback = "1m"
    try:
        from opentide.platforms.elastic.durations import duration_seconds, format_duration

        total_secs = duration_seconds(from_val.removeprefix("now-"))
        interval_secs = duration_seconds(interval)
        if total_secs >= interval_secs:
            lookback = format_duration(total_secs - interval_secs)
    except Exception:
        pass

    scheduling_dict: dict[str, Any] = {
        "interval": interval,
        "lookback": lookback,
    }
    if rule.get("max_signals"):
        scheduling_dict["max_alerts"] = rule["max_signals"]
    elastic_block["scheduling"] = scheduling_dict

    # Severity & Risk
    if rule.get("severity_mapping"):
        elastic_block["severity"] = {
            "default": alert_severity,
            "mapping": copy.deepcopy(rule["severity_mapping"]),
        }
    if rule.get("risk_score") is not None:
        if rule.get("risk_score_mapping"):
            elastic_block["risk"] = {
                "score": rule["risk_score"],
                "mapping": copy.deepcopy(rule["risk_score_mapping"]),
            }
        else:
            elastic_block["risk"] = rule["risk_score"]

    # Suppression
    if rule.get("alert_suppression"):
        supp = rule["alert_suppression"]
        supp_out: dict[str, Any] = {}
        if rule_type != "threshold" and supp.get("group_by"):
            supp_out["group_by"] = list(supp["group_by"])
        if supp.get("duration"):
            dur = supp["duration"]
            if isinstance(dur, dict):
                supp_out["duration"] = f"{dur.get('value')}{dur.get('unit')}"
            elif isinstance(dur, str):
                supp_out["duration"] = dur
        if supp.get("missing_fields_strategy"):
            supp_out["missing_fields_strategy"] = supp["missing_fields_strategy"]
        if supp_out:
            elastic_block["suppression"] = supp_out

    # Filters
    if rule.get("filters") and rule_type not in ("esql", "machine_learning"):
        filters_out = []
        for f in rule["filters"]:
            meta = f.get("meta") or {}
            if meta.get("type") == "phrase" and meta.get("key") and meta.get("params", {}).get("query"):
                filters_out.append(
                    {
                        "field": meta["key"],
                        "value": str(meta["params"]["query"]),
                        "negate": bool(meta.get("negate", False)),
                    }
                )
            else:
                raw_item = copy.deepcopy(f)
                raw_item.pop("$state", None)
                filters_out.append(raw_item)
        if filters_out:
            elastic_block["filters"] = filters_out

    # Highlighted fields
    inv_fields = rule.get("investigation_fields", {}).get("field_names") or []
    if inv_fields:
        elastic_block["highlighted_fields"] = list(inv_fields)

    # Required fields
    if rule.get("required_fields"):
        req_fields = []
        valid_types = {
            "keyword", "constant_keyword", "wildcard", "text", "match_only_text",
            "long", "integer", "short", "byte", "unsigned_long", "double", "float",
            "half_float", "scaled_float", "date", "date_nanos", "boolean", "ip",
            "version", "binary", "geo_point", "geo_shape", "object", "flattened", "nested",
        }
        for rf in rule["required_fields"]:
            if isinstance(rf, dict) and rf.get("name"):
                rf_type = rf.get("type", "keyword")
                if rf_type not in valid_types:
                    rf_type = "keyword"
                req_fields.append({"name": rf["name"], "type": rf_type})
        if req_fields:
            elastic_block["required_fields"] = req_fields

    # Integrations
    if rule.get("related_integrations"):
        rel_ints = []
        for ri in rule["related_integrations"]:
            if isinstance(ri, dict) and ri.get("package"):
                if ri.get("integration"):
                    rel_ints.append(
                        {
                            "package": ri["package"],
                            "integration": ri["integration"],
                            "version": ri.get("version", "*"),
                        }
                    )
                else:
                    rel_ints.append(ri["package"])
        if rel_ints:
            elastic_block["integration"] = rel_ints

    # Guides (investigation note, setup)
    guide_dict: dict[str, Any] = {}
    if rule.get("note"):
        guide_dict["investigation"] = rule["note"].strip()
    if rule.get("setup"):
        guide_dict["setup"] = rule["setup"].strip()
    if guide_dict:
        elastic_block["guide"] = guide_dict

    # False positives
    if rule.get("false_positives"):
        elastic_block["false_positives"] = list(rule["false_positives"])

    # Tags
    if rule.get("tags"):
        elastic_block["tags"] = [t for t in rule["tags"] if t != "OpenTide"]

    # Overrides
    overrides_dict: dict[str, Any] = {}
    if rule.get("rule_name_override"):
        overrides_dict["name"] = rule["rule_name_override"]
    if rule.get("timestamp_override"):
        overrides_dict["timestamp"] = rule["timestamp_override"]
    if rule.get("timestamp_override_fallback_disabled") is not None:
        overrides_dict["disable_fallback"] = rule["timestamp_override_fallback_disabled"]
    if overrides_dict:
        elastic_block["overrides"] = overrides_dict

    # Actions
    actions_dict: dict[str, Any] = {}
    if rule.get("actions"):
        actions_dict["notify"] = copy.deepcopy(rule["actions"])
    if rule.get("response_actions"):
        resp_actions = []
        for ra in rule["response_actions"]:
            aid = ra.get("action_type_id")
            params = ra.get("params") or {}
            if aid == ".endpoint":
                cmd = params.get("command")
                act_item = {"endpoint": cmd}
                if params.get("comment"):
                    act_item["comment"] = params["comment"]
                if params.get("config", {}).get("field"):
                    act_item["field"] = params["config"]["field"]
                resp_actions.append(act_item)
            elif aid == ".osquery":
                resp_actions.append({"osquery": copy.deepcopy(params)})
        if resp_actions:
            actions_dict["respond"] = resp_actions
    if rule.get("timeline_id"):
        actions_dict["timeline"] = {
            "id": rule["timeline_id"],
            "title": rule.get("timeline_title", ""),
        }
    if actions_dict:
        elastic_block["actions"] = actions_dict

    # Exceptions
    exc_list = rule.get("exceptions_list") or []
    has_endpoint = any(isinstance(e, dict) and e.get("type") == "endpoint" for e in exc_list)
    custom_lists = [
        {
            "id": e["id"],
            "list_id": e["list_id"],
            "namespace_type": e.get("namespace_type", "single"),
            "type": e.get("type", "detection"),
        }
        for e in exc_list
        if isinstance(e, dict) and e.get("type") in ("detection", "rule_default")
    ]
    if has_endpoint or custom_lists:
        elastic_block["exceptions"] = {
            "endpoint": has_endpoint,
            "lists": custom_lists or None,
        }

    # Type-specific blocks
    if rule_type == "threshold" and rule.get("threshold"):
        t_in = rule["threshold"]
        t_card = None
        if t_in.get("cardinality") and isinstance(t_in["cardinality"], list) and t_in["cardinality"]:
            c0 = t_in["cardinality"][0]
            t_card = {"field": c0.get("field"), "value": c0.get("value")}
        elastic_block["threshold"] = {
            "field": list(t_in.get("field") or []),
            "value": t_in.get("value", 1),
            "cardinality": t_card,
        }

    if rule_type == "new_terms":
        elastic_block["new_terms"] = {
            "fields": list(rule.get("new_terms_fields") or []),
            "history_window_start": str(rule.get("history_window_start", "now-14d")).removeprefix("now-"),
        }

    if rule_type == "eql":
        eql_dict: dict[str, Any] = {}
        for k in ("timestamp_field", "event_category_override", "tiebreaker_field"):
            if rule.get(k):
                eql_dict[k] = rule[k]
        if eql_dict:
            elastic_block["eql"] = eql_dict

    if rule_type == "threat_match":
        threat_mapping_in = rule.get("threat_mapping") or []
        threat_mapping_out = []
        for g in threat_mapping_in:
            entries = []
            for e in g.get("entries", []):
                entries.append(
                    {
                        "field": e.get("field"),
                        "value": e.get("value"),
                        "type": e.get("type", "mapping"),
                        "negate": e.get("negate"),
                    }
                )
            threat_mapping_out.append({"entries": entries})

        threat_filters_out = []
        for f in rule.get("threat_filters") or []:
            meta = f.get("meta") or {}
            if meta.get("type") == "phrase" and meta.get("key") and meta.get("params", {}).get("query"):
                threat_filters_out.append(
                    {
                        "field": meta["key"],
                        "value": str(meta["params"]["query"]),
                        "negate": bool(meta.get("negate", False)),
                    }
                )
            else:
                raw_item = copy.deepcopy(f)
                raw_item.pop("$state", None)
                threat_filters_out.append(raw_item)

        elastic_block["threat"] = {
            "index": list(rule.get("threat_index") or []),
            "query": rule.get("threat_query", ""),
            "language": rule.get("threat_language") or "kuery",
            "indicator_path": rule.get("threat_indicator_path"),
            "mapping": threat_mapping_out,
            "filters": threat_filters_out or None,
        }

    if rule_type == "machine_learning":
        elastic_block["machine_learning"] = {
            "job_id": copy.deepcopy(rule.get("machine_learning_job_id", "")),
            "anomaly_threshold": int(rule.get("anomaly_threshold", 50)),
        }

    # Building block
    if rule.get("building_block_type") == "default":
        elastic_block["building_block"] = True

    # Assemble OpenTide rule document
    refs_dict: dict[str, str] = {}
    if rule.get("references"):
        for i, ref in enumerate(rule["references"], start=1):
            refs_dict[str(i)] = ref

    doc: dict[str, Any] = {
        "name": rule_name,
        "metadata": {
            "uuid": rule_id,
            "schema": "rule::1.0",
            "version": 1,
            "created": created,
            "modified": modified,
            "tlp": "clear",
            "author": author,
            "contributors": contributors or None,
        },
        "description": description,
        "techniques": techniques,
        "references": {"public": refs_dict} if refs_dict else None,
        "response": {
            "alert_severity": alert_severity,
            "procedure": {
                "analysis": str(rule.get("note", "")).strip() or None,
            },
        },
        "configurations": {
            "elastic": _clean_empty(elastic_block),
        },
    }

    return _clean_empty(doc)


def run(
    destination: Path = Path("Imported"),
    space: str = "default",
    make_custom: bool = True,
    include_prebuilt: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    """Execute rule extraction from Elastic Security cluster."""
    from opentide.core.registry import OpenTide
    from opentide.platforms.elastic.client import ElasticClient

    OpenTide.initialise()
    elastic_config = getattr(OpenTide.Configuration.Systems, "Elastic", None)
    if not elastic_config or not elastic_config.tenants:
        raise RuntimeError("No tenants configured for Elastic in .opentide/configurations/platforms/elastic.toml")

    # Select tenant matching space or first tenant
    tenant = next((t for t in elastic_config.tenants if getattr(t.setup, "space", "default") == space), elastic_config.tenants[0])

    client = ElasticClient(
        url=tenant.setup.url,
        elasticsearch_url=tenant.setup.elasticsearch_url,
        api_key=getattr(tenant.setup, "api_key", ""),
        space=getattr(tenant.setup, "space", "default"),
        verify_ssl=getattr(tenant.setup, "ssl", True),
    )

    dest_dir = destination.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    page = 1
    per_page = 100
    total_extracted = 0
    exported_rules: list[dict[str, Any]] = []

    while True:
        resp = client.find_rules(page=page, per_page=per_page)
        rules = resp.get("data", [])
        if not rules:
            break

        for rule in rules:
            is_prebuilt = bool(rule.get("immutable") or rule.get("rule_source", {}).get("type") == "external")
            if is_prebuilt and not include_prebuilt:
                continue

            doc = kibana_to_opentide(rule, make_custom=make_custom)
            filename = f"{sanitize_filename(doc['name'])}.yaml"
            out_file = dest_dir / filename
            with open(out_file, "w", encoding="utf-8") as f:
                yaml.dump(doc, f, Dumper=IndentedYamlDumper, sort_keys=False)
            total_extracted += 1
            exported_rules.append({"name": doc["name"], "uuid": doc["metadata"]["uuid"], "file": str(out_file)})

        if len(rules) < per_page:
            break
        page += 1

    return {
        "status": "success",
        "tenant": tenant.name,
        "space": space,
        "extracted_count": total_extracted,
        "destination": str(dest_dir),
    }
