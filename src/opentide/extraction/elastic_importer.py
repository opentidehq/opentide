"""Export detection rules from Elastic Security and convert to opentide rules (RFC 0007)."""

from __future__ import annotations

import copy
import uuid
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)

# Dedicated opentide namespace for UUIDs derived from prebuilt Elastic rule_ids.
OPENTIDE_MIGRATION_NS = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://opentide.org/ns/elastic-rule-migration"
)

_VALID_FIELD_TYPES = frozenset(
    {
        "keyword",
        "constant_keyword",
        "wildcard",
        "text",
        "match_only_text",
        "long",
        "integer",
        "short",
        "byte",
        "unsigned_long",
        "double",
        "float",
        "half_float",
        "scaled_float",
        "date",
        "date_nanos",
        "boolean",
        "ip",
        "version",
        "binary",
        "geo_point",
        "geo_shape",
        "object",
        "flattened",
        "nested",
    }
)


class IndentedYamlDumper(yaml.SafeDumper):
    """YAML dumper preserving list indents and formatting."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
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


def _is_prebuilt(rule: dict[str, Any]) -> bool:
    return bool(rule.get("immutable") or rule.get("rule_source", {}).get("type") == "external")


def _date_math_duration(value: Any) -> str:
    """Kibana ``now-<n><unit>`` to an RFC 0007 duration. Kibana accepts weeks; RFC 0007 does not."""
    text = str(value).strip().removeprefix("now-")
    if text.endswith("w") and text[:-1].isdigit():
        return f"{int(text[:-1]) * 7}d"
    return text


def _only(entry: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Keep the keys the RFC 0007 sub-model declares; Kibana returns extras it forbids."""
    return {key: entry[key] for key in keys if key in entry}


def _extract_filter(entry: dict[str, Any]) -> dict[str, Any]:
    meta = entry.get("meta") or {}
    query_val = meta.get("params", {}).get("query")
    # The shorthand compiles to disabled: false, so a disabled filter stays raw.
    if meta.get("type") == "phrase" and meta.get("key") and query_val and not meta.get("disabled"):
        return {
            "field": meta["key"],
            "value": str(query_val),
            "negate": bool(meta.get("negate", False)),
        }
    raw_item = copy.deepcopy(entry)
    raw_item.pop("$state", None)
    return raw_item


def kibana_to_opentide(
    rule: dict[str, Any],
    make_custom: bool = True,
    uuid_override: str | None = None,
    name_suffix: str = " (Custom)",
) -> dict[str, Any]:
    """Convert an exported Kibana detection engine rule dict into an opentide DetectionRule dict."""
    rule_type = rule.get("type", "query")
    prebuilt = _is_prebuilt(rule)

    raw_rule_id = rule.get("rule_id") or rule.get("id") or ""
    if uuid_override:
        rule_id = uuid_override
    elif make_custom and prebuilt:
        rule_id = str(uuid.uuid5(OPENTIDE_MIGRATION_NS, raw_rule_id))
    else:
        rule_id = raw_rule_id

    rule_name = str(rule.get("name", "Unnamed Rule"))
    if make_custom and name_suffix and prebuilt:
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

    # STAGING is a PREVIEW strategy, which deploys enabled. A rule that is
    # disabled in Kibana must come back as a DISABLEMENT status (RFC 0007 §3).
    status = "PRODUCTION" if rule.get("enabled", False) else "DISABLED"

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
        if rule_type in ("query", "threshold", "new_terms", "threat_match") and lang in (
            "kuery",
            "lucene",
        ):
            elastic_block["language"] = lang

    # Index
    if rule_type not in ("esql", "machine_learning"):
        if rule.get("data_view_id"):
            elastic_block["data_view_id"] = rule["data_view_id"]
        elif rule.get("index"):
            elastic_block["index"] = list(rule["index"])

    # Scheduling: Kibana from = now-(interval + lookback) (RFC 0007 §3 Schedule)
    from opentide.platforms.elastic.durations import duration_seconds, format_duration

    interval = rule.get("interval", "5m")
    from_val = rule.get("from", "now-6m")
    try:
        total_secs = duration_seconds(_date_math_duration(from_val), allow_zero=True)
        interval_secs = duration_seconds(interval)
    except ValueError:
        logger.warning(
            "elastic_import_schedule_defaulted",
            rule=rule.get("name"),
            interval=interval,
            **{"from": from_val},
        )
        lookback = "1m"
    else:
        if total_secs < interval_secs:
            # The look-back window is shorter than the interval; RFC 0007 cannot
            # express that, so the closest window is lookback 0m (from = interval).
            logger.warning(
                "elastic_import_window_widened",
                rule=rule.get("name"),
                interval=interval,
                **{"from": from_val},
            )
        lookback = format_duration(max(total_secs - interval_secs, 0))

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
            "mapping": [
                _only(m, ("field", "value", "operator", "severity"))
                for m in rule["severity_mapping"]
            ],
        }
    if rule.get("risk_score") is not None:
        if rule.get("risk_score_mapping"):
            elastic_block["risk"] = {
                "score": rule["risk_score"],
                "mapping": [
                    _only(m, ("field", "operator", "value")) for m in rule["risk_score_mapping"]
                ],
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
        filters_out = [_extract_filter(f) for f in rule["filters"]]
        if filters_out:
            elastic_block["filters"] = filters_out

    # Highlighted fields
    inv_fields = (rule.get("investigation_fields") or {}).get("field_names") or []
    if inv_fields:
        elastic_block["highlighted_fields"] = list(inv_fields)

    # Required fields
    if rule.get("required_fields"):
        req_fields = []
        for rf in rule["required_fields"]:
            if isinstance(rf, dict) and rf.get("name"):
                rf_type = rf.get("type")
                if rf_type not in _VALID_FIELD_TYPES:
                    # FieldType is closed in RFC 0007; never relabel a field's type.
                    logger.warning(
                        "elastic_import_required_field_dropped",
                        rule=rule.get("name"),
                        field=rf["name"],
                        type=rf_type,
                    )
                    continue
                req_fields.append({"name": rf["name"], "type": rf_type})
        if req_fields:
            elastic_block["required_fields"] = req_fields

    # Integrations
    if rule.get("related_integrations"):
        rel_ints = []
        for ri in rule["related_integrations"]:
            if isinstance(ri, dict) and ri.get("package"):
                version = ri.get("version") or "*"
                if ri.get("integration") or version != "*":
                    # The string shorthand compiles to version "*"; keep any real range.
                    item = {"package": ri["package"], "version": version}
                    if ri.get("integration"):
                        item["integration"] = ri["integration"]
                    rel_ints.append(item)
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
                if cmd not in ("isolate", "kill-process", "suspend-process", "runscript"):
                    # RFC 0007 response_action allows only these; drop the action, keep the rule.
                    logger.warning(
                        "skipping_unsupported_endpoint_response_action",
                        rule=rule_name,
                        command=cmd,
                    )
                    continue
                act_item = {"endpoint": cmd}
                if params.get("comment"):
                    act_item["comment"] = params["comment"]
                config = params.get("config") or {}
                # overwrite: true is Kibana's default field; only a custom field is authored.
                if config.get("field") and not config.get("overwrite"):
                    act_item["field"] = config["field"]
                resp_actions.append(act_item)
            elif aid == ".osquery":
                if isinstance(params, dict) and params.get("query"):
                    resp_actions.append({"osquery": copy.deepcopy(params)})
                else:
                    logger.warning(
                        "skipping_unsupported_osquery_response_action",
                        rule=rule_name,
                        reason="osquery response action has no inline query (pack/saved query)",
                    )
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
        card_list = t_in.get("cardinality")
        if isinstance(card_list, list) and card_list:
            c0 = card_list[0]
            t_card = {"field": c0.get("field"), "value": c0.get("value")}
        t_field = t_in.get("field") or []
        if isinstance(t_field, str):
            # Kibana's ThresholdField is a string or a list; list("a.b") splits it into letters.
            t_field = [t_field]
        elastic_block["threshold"] = {
            "field": list(t_field),
            "value": t_in.get("value", 1),
            "cardinality": t_card,
        }

    if rule_type == "new_terms":
        raw_hist = str(rule.get("history_window_start", "now-14d"))
        elastic_block["new_terms"] = {
            "fields": list(rule.get("new_terms_fields") or []),
            "history_window_start": _date_math_duration(raw_hist),
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
                entry_out: dict[str, Any] = {
                    "field": e.get("field"),
                    "value": e.get("value"),
                    "type": e.get("type", "mapping"),
                }
                if e.get("negate") is not None:
                    entry_out["negate"] = e["negate"]
                entries.append(entry_out)
            threat_mapping_out.append({"entries": entries})

        threat_filters_out = [_extract_filter(f) for f in (rule.get("threat_filters") or [])]

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

    # Assemble opentide rule document
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
            # A cluster's rules are the organisation's own detections. CLEAR
            # would let `share push` publish them to anyone; the Sentinel
            # importer defaults to amber too.
            "tlp": "amber",
            "author": author,
            "contributors": contributors or None,
        },
        "description": description,
        "techniques": techniques,
        "references": {"public": refs_dict} if refs_dict else None,
        # The note is imported once, as guide.investigation; compile reads it from there.
        "response": {"alert_severity": alert_severity},
        "configurations": {
            "elastic": _clean_empty(elastic_block),
        },
    }

    return _clean_empty(doc)


def _unwritable_reason(doc: dict[str, Any]) -> str | None:
    """Why *doc* must not be written, or None. Every written file must load as rule::1.0."""
    rule_id = str(doc.get("metadata", {}).get("uuid", ""))
    try:
        uuid.UUID(rule_id)
    except ValueError:
        # RFC 0007 §2 decision 4: identity is the MDR UUID, sent as rule_id.
        # Deriving a new one would deploy a duplicate next to the existing rule.
        return f"Kibana rule_id {rule_id!r} is not a UUID"
    from opentide.loading.rule_loader import load_rule_from_dict

    try:
        load_rule_from_dict(copy.deepcopy(doc))
    except Exception as exc:  # unsupported shape, e.g. a saved_query rule
        return f"does not validate as platform::elastic::1.0: {str(exc).splitlines()[0]}"
    return None


def run(
    destination: Path = Path("Imported"),
    space: str = "default",
    make_custom: bool = True,
    include_prebuilt: bool = False,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Execute rule extraction from Elastic Security cluster."""
    from opentide.core.registry import Opentide
    from opentide.platforms.elastic.client import ElasticClient

    Opentide.initialise()
    elastic_config = getattr(Opentide.Configuration.Systems, "Elastic", None)
    if not elastic_config or not elastic_config.tenants:
        raise RuntimeError(
            "No tenants configured for Elastic in .opentide/configurations/platforms/elastic.toml"
        )

    tenant = next(
        (t for t in elastic_config.tenants if getattr(t.setup, "space", "default") == space),
        None,
    )
    if tenant is None:
        # Never fall back to another tenant: that exports a different space
        # while the result still reports the requested one.
        raise RuntimeError(f"No Elastic tenant is configured for Kibana space '{space}'")

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
    written: set[str] = set()
    skipped: list[dict[str, str]] = []

    while True:
        resp = client.find_rules(page=page, per_page=per_page)
        rules = resp.get("data", [])
        if not rules:
            break

        for rule in rules:
            is_prebuilt = _is_prebuilt(rule)
            # Prebuilt rules can only be redeployed when converted to custom rules
            # with a derived UUID (RFC 0007 §5 refuses to modify prebuilt rules).
            if is_prebuilt and (not include_prebuilt or not make_custom):
                continue

            doc = kibana_to_opentide(rule, make_custom=make_custom)
            reason = _unwritable_reason(doc)
            if reason:
                logger.warning("elastic_import_rule_skipped", rule=doc.get("name"), reason=reason)
                skipped.append({"name": str(doc.get("name")), "reason": reason})
                continue
            # Rule names are not unique in Kibana; never overwrite a file from this run.
            stem = sanitize_filename(doc["name"])
            if stem.lower() in written:
                stem = f"{stem} {doc['metadata']['uuid'][:8]}"
            written.add(stem.lower())
            filename = f"{stem}.yaml"
            out_file = dest_dir / filename
            with open(out_file, "w", encoding="utf-8") as f:
                yaml.dump(doc, f, Dumper=IndentedYamlDumper, sort_keys=False)
            total_extracted += 1
            exported_rules.append(
                {
                    "name": doc["name"],
                    "uuid": doc["metadata"]["uuid"],
                    "file": str(out_file),
                }
            )

        if len(rules) < per_page:
            break
        page += 1

    return {
        "status": "success",
        "tenant": tenant.name,
        "space": space,
        "extracted_count": total_extracted,
        "skipped": skipped,
        "destination": str(dest_dir),
    }
