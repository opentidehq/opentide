#!/usr/bin/env python3
"""Generate catalogs/spl/datamodels.toml from a splunk/pytest-splunk-addon checkout.

pytest-splunk-addon (Apache-2.0) ships one JSON file per Splunk Common
Information Model (CIM) data model in pytest_splunk_addon/data_models/: the
datasets, their parent/child lineage, every field name and the values CIM
expects for some fields. Splunk uses those files to test add-ons for CIM
compliance. This script keeps facts only (names, lineage, expected values);
the `docs` sentences are written here.

What the files leave out, and this script adds (each with its reason):

- Every dataset inherits `_time`, `host`, `source` and `sourcetype` from the
  CIM base event.
- `tag` and the asset and identity fields Enterprise Security adds to every
  root dataset (`dest_bunit`, `dest_category`, `dest_priority`, the same for
  `src`, `user`, `src_user` and `dvc`, and `dest_requires_av`,
  `dest_should_timesync`, `dest_should_update`, `dest_is_expected`). The CIM
  manual lists them on each model's page ("automatically provided by asset
  and identity correlation features").
- Fields and datasets CIM 4.x defines that the files (CIM 5 and later)
  dropped (`LEGACY_FIELDS`), since searches written for a CIM 4.x install
  still read them.
- Object names: a few files use the display name ("All Email", "Malware
  Attacks"); tstats and `datamodel=` use the object name (`All_Email`).
- Datasets and models the files do not carry: `Traffic_By_Action` as the
  parent of `Allowed_Traffic` / `Blocked_Traffic`, `Deferred_Malware`,
  `Virtual_OS.Tools`, the deprecated CIM models (Application_State,
  Change_Analysis) and the data models Enterprise Security adds (Risk,
  Threat_Intelligence, ...). Models and datasets without a complete field
  list carry `complete = false`: the engine knows their names and never
  checks their fields.

The engine reports `spl_unknown_datamodel_field` only for a field that is
missing from a `complete` dataset *and* is a near miss of one it has, so a
field a site adds to its CIM models is never an error.

Usage:
    python scripts/sync_cim_datamodels.py --source ../pytest-splunk-addon
    python scripts/sync_cim_datamodels.py --source ../pytest-splunk-addon --check
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "catalogs/spl/datamodels.toml"
CIM_DOCS = "https://docs.splunk.com/Documentation/CIM/latest/User/"

BASE_FIELDS = ["_time", "host", "source", "sourcetype"]
ENRICHED = ["dest", "src", "user", "src_user", "dvc"]
ENRICHMENT_SUFFIXES = ["_bunit", "_category", "_priority"]
DEST_ENRICHMENT = [
    "dest_requires_av",
    "dest_should_timesync",
    "dest_should_update",
    "dest_is_expected",
]

# Files whose model_name is empty or wrong.
MODEL_NAMES = {"Interprocess Messaging.json": "Interprocess_Messaging"}
# Display names in the files that are not the object name tstats uses.
OBJECT_NAMES = {("JVM", "Event_Signatures"): "JVM"}
# CIM manual page for each model, where it is not the model name.
PAGES = {
    "Compute_Inventory": "Inventory",
    "Network_Resolution": "NetworkResolution",
    "Network_Sessions": "NetworkSessions",
    "Network_Traffic": "NetworkTraffic",
    "Intrusion_Detection": "IntrusionDetection",
    "Ticket_Management": "TicketManagement",
    "Data_Access": "DataAccess",
    "Event_Signatures": "EventSignatures",
    "Interprocess_Messaging": "InterprocessMessaging",
    "JVM": "JavaVirtualMachines",
}

# Datasets the files place under another parent than the CIM manual does:
# (model, lineage in the file) -> lineage in CIM.
MOVES = {
    ("Network_Traffic", "All_Traffic.Allowed_Traffic"): "All_Traffic.Traffic_By_Action.Allowed_Traffic",
    ("Network_Traffic", "All_Traffic.Blocked_Traffic"): "All_Traffic.Traffic_By_Action.Blocked_Traffic",
}
# Datasets the files leave out, added with no fields of their own.
EXTRA_DATASETS = {
    "Malware": ["Malware_Attacks.Deferred_Malware"],
    "Compute_Inventory": ["All_Inventory.Virtual_OS.Tools"],
    # CIM 4.x object names.
    "Event_Signatures": ["Signatures"],
    "Updates": ["Updates.Update_Errors"],
}
# Fields CIM 4.x defines that the files (CIM 5 and later) dropped. Searches
# written for a CIM 4.x install still read them. Source: the CIM 4.20 manual,
# https://docs.splunk.com/Documentation/CIM/4.20.0/User/<Model>.
LEGACY_FIELDS = {
    ("Authentication", "Authentication"): ["dest_nt_domain", "src_nt_domain", "src_user_id"],
    ("Certificates", "All_Certificates.SSL"): ["ssl_issuer_state"],
    ("Data_Access", "Data_Access"): ["tenant_id"],
    ("Event_Signatures", "Signatures"): ["dest", "signature", "signature_id", "vendor_product"],
    ("Network_Resolution", "DNS"): ["dest_port", "src_port"],
}

# Data models the files do not carry. Their names are known; their fields are
# not checked (complete = false).
OPEN_MODELS = [
    {
        "name": "Risk.All_Risk",
        "model": "Risk",
        "lineage": "All_Risk",
        "docs": "Risk events from Enterprise Security risk-based alerting (not part of the CIM).",
        "fields": [
            "risk_object",
            "risk_object_type",
            "risk_score",
            "calculated_risk_score",
            "source",
            "analyticstories",
            "tag",
            "annotations.mitre_attack.mitre_tactic",
            "annotations.mitre_attack.mitre_tactic_id",
            "annotations.mitre_attack.mitre_technique_id",
        ],
        "citation": "https://docs.splunk.com/Documentation/ES/latest/User/RiskScoring",
    },
    {
        "name": "Application_State.All_Application_State",
        "model": "Application_State",
        "lineage": "All_Application_State",
        "docs": "Deprecated CIM model (replaced by Endpoint).",
        "citation": CIM_DOCS + "ApplicationState",
    },
    {
        "name": "Change_Analysis.All_Changes",
        "model": "Change_Analysis",
        "lineage": "All_Changes",
        "docs": "Deprecated CIM model (replaced by Change).",
        "citation": CIM_DOCS + "ChangeAnalysis",
    },
]
OPEN_MODEL_NAMES = [
    "Assets_And_Identities",
    "Domain_Analysis",
    "Identity_Management",
    "Incident_Management",
    "Splunk_Audit",
    "Splunk_CIM_Validation",
    "Threat_Intelligence",
    "UEBA",
]

# Short descriptions for the datasets detections read most.
DOCS = {
    "Endpoint.Processes": "Process creation (CIM Endpoint).",
    "Endpoint.Filesystem": "File create/modify/delete.",
    "Endpoint.Registry": "Registry changes.",
    "Endpoint.Services": "Service install / start.",
    "Endpoint.Ports": "Listening ports.",
    "Authentication.Authentication": "Logon / auth events.",
    "Network_Traffic.All_Traffic": "Firewall / flow.",
    "Web.Web": "Proxy / HTTP.",
    "Intrusion_Detection.IDS_Attacks": "IDS / IPS alerts.",
    "Malware.Malware_Attacks": "AV / EDR malware.",
    "Change.All_Changes": "Account / object change.",
    "Network_Resolution.DNS": "DNS queries.",
    "Email.All_Email": "Email flow.",
    "Alerts.Alerts": "Product alerts.",
}


def object_name(model: str, name: str) -> str:
    return OBJECT_NAMES.get((model, name), name.replace(" ", "_"))


def walk(model: str, objects: list[dict], parent: str, out: dict[str, dict]) -> None:
    for obj in objects:
        lineage = f"{parent}.{object_name(model, obj['name'])}" if parent else object_name(model, obj["name"])
        fields = [f["name"] for f in obj.get("fields", [])]
        values = {
            f["name"]: [str(v) for v in f["expected_values"]]
            for f in obj.get("fields", [])
            if f.get("expected_values")
        }
        out[MOVES.get((model, lineage), lineage)] = {"fields": fields, "values": values}
        walk(model, obj.get("child_dataset", []), lineage, out)


def enrich(fields: list[str], root: bool) -> list[str]:
    extra = []
    if root:
        extra = list(BASE_FIELDS) + ["tag"]
        for base in ENRICHED:
            extra += [base + s for s in ENRICHMENT_SUFFIXES]
        extra += DEST_ENRICHMENT
    seen = set()
    out = []
    for f in fields + extra:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def load(source: Path) -> list[dict]:
    rows = []
    for path in sorted((source / "pytest_splunk_addon/data_models").glob("*.json")):
        doc = json.loads(path.read_text())
        model = MODEL_NAMES.get(path.name) or doc["model_name"]
        datasets: dict[str, dict] = {}
        walk(model, doc["objects"], "", datasets)
        for extra in EXTRA_DATASETS.get(model, []):
            datasets.setdefault(extra, {"fields": [], "values": {}})
        for (legacy_model, lineage), names in LEGACY_FIELDS.items():
            if legacy_model == model:
                have = datasets[lineage]["fields"]
                have += [n for n in names if n not in have]
        # Intermediate datasets a move introduced.
        for lineage in list(datasets):
            parts = lineage.split(".")
            for i in range(1, len(parts)):
                datasets.setdefault(".".join(parts[:i]), {"fields": [], "values": {}})
        for lineage in sorted(datasets, key=lambda l: (l.split(".")[0], l.count("."), l)):
            data = datasets[lineage]
            name = lineage.split(".")[-1]
            row = {
                "name": f"{model}.{name}",
                "model": model,
                "prefix": lineage.split(".")[0],
                "lineage": lineage,
                "docs": DOCS.get(f"{model}.{name}")
                or (f"{name} dataset of the {model} CIM data model."),
                "complete": True,
                "fields": enrich(data["fields"], "." not in lineage),
                "values": data["values"],
                "citation": CIM_DOCS + PAGES.get(model, model),
            }
            rows.append(row)
    for extra in OPEN_MODELS:
        rows.append(
            {
                "name": extra["name"],
                "model": extra["model"],
                "prefix": extra["lineage"].split(".")[0],
                "lineage": extra["lineage"],
                "docs": extra["docs"],
                "complete": False,
                "fields": extra.get("fields", []),
                "values": {},
                "citation": extra["citation"],
            }
        )
    return rows


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def toml_list(values: list[str]) -> str:
    return "[" + ", ".join(toml_str(v) for v in values) + "]"


def render(rows: list[dict], source: str) -> str:
    lines = [
        "# Splunk CIM data models: datasets, lineage and field names.",
        "# Generated by scripts/sync_cim_datamodels.py from",
        f"# {source} (pytest_splunk_addon/data_models, Apache-2.0).",
        "# Do not edit by hand; change the script and regenerate.",
        "#",
        "# name     `datamodel=` form: Model.Dataset (the dataset's object name)",
        "# prefix   the root dataset: tstats fields are `<prefix>.<field>` until",
        "#          `drop_dm_object_name(<prefix>)` runs",
        "# lineage  root to dataset; a field a child dataset defines is",
        "#          `<lineage>.<field>` (All_Email.Filtering.filter_action)",
        "# fields   the fields the dataset defines (children inherit their parents')",
        "# values   values CIM expects for a field (completion and hover only)",
        "# complete false: the fields are not a complete list and are never checked",
        "",
        "models = " + toml_list(OPEN_MODEL_NAMES),
        "",
    ]
    for row in rows:
        lines.append("[[datamodels]]")
        for key in ("name", "model", "prefix", "lineage", "docs"):
            lines.append(f"{key} = {toml_str(row[key])}")
        lines.append(f"complete = {'true' if row['complete'] else 'false'}")
        lines.append(f"fields = {toml_list(row['fields'])}")
        if row["values"]:
            inner = ", ".join(f"{k} = {toml_list(v)}" for k, v in sorted(row["values"].items()))
            lines.append(f"values = {{ {inner} }}")
        lines.append(f"citation = {toml_str(row['citation'])}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    commit = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    rows = load(source)
    text = render(rows, f"splunk/pytest-splunk-addon@{commit}")
    if args.check:
        current = OUT.read_text()
        # The commit line changes with every checkout; compare the rows.
        strip = lambda t: "\n".join(l for l in t.splitlines() if not l.startswith("# splunk/"))
        if strip(current) != strip(text):
            sys.exit(f"{OUT.relative_to(ROOT)} is stale: rerun scripts/sync_cim_datamodels.py")
        print(f"{OUT.relative_to(ROOT)} is current")
        return
    OUT.write_text(text)
    print(f"splunk/pytest-splunk-addon@{commit}: {len(rows)} datasets")


if __name__ == "__main__":
    main()
