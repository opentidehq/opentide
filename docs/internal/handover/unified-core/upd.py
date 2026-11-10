#!/usr/bin/env python3
"""Edit dashboard data. Usage:
  upd.py item <ID> key=value ...      # e.g. upd.py item UC-X.3 pr=#849 stage="In review" base="UC-0.4 (#848)"
  upd.py event "<text>"               # appends an event at now (UTC)
  upd.py decision <ID> status=Done    # or: upd.py decision new <ID> <where> <kind> "<ask>"
Then re-uploads are done by the orchestrator (Artifact asset + ArtifactData update)."""
import json, sys, datetime
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def load(n): return json.load(open(n))
def save(n, d): json.dump(d, open(n, "w"), indent=1)
kind = sys.argv[1]
if kind == "item":
    d = load("items.json"); rid = sys.argv[2]
    row = next(r for r in d["rows"] if r["id"] == rid)
    for kv in sys.argv[3:]:
        k, v = kv.split("=", 1); row[k] = v
    save("items.json", d)
    stage_to = {"Merged": "Merged", "Ready for review": "Ready for review"}
    e = load("epic.json")
    for r in e["rows"]:
        if r["id"] == rid:
            r["status"] = stage_to.get(row["stage"], "In progress" if row["stage"] in ("Building", "Finishing", "In review", "Fixing", "Blocked") else "Not started")
            r["pr"] = row.get("pr", r.get("pr", "—"))
    save("epic.json", e)
elif kind == "pr":
    d = load("prs.json"); key = sys.argv[2]
    row = next((r for r in d["rows"] if r["pr"] == key), None)
    if row is None:
        row = {"pr": key, "item": "", "opened": now, "stage": "In review", "ci": "—", "review_rounds": 0, "findings_raised": 0, "findings_open": 0, "rust_tests": None}
        d["rows"].append(row)
    for kv in sys.argv[3:]:
        k, v = kv.split("=", 1)
        row[k] = int(v) if v.isdigit() else (None if v == "null" else v)
    save("prs.json", d)
elif kind == "snapshot":
    e = load("epic.json")["rows"]; p = load("prs.json")["rows"]; h = load("history.json")
    c = lambda s: sum(1 for r in e if r["status"] == s)
    h["rows"].append({"at": now, "merged": c("Merged"), "ready": c("Ready for review"), "progress": c("In progress"), "todo": c("Not started"),
                      "prs_open": sum(1 for r in p if r["stage"] != "Merged")})
    save("history.json", h)
elif kind == "event":
    d = load("events.json"); d["rows"].append({"at": now, "what": sys.argv[2]}); save("events.json", d)
elif kind == "decision":
    d = load("decisions.json")
    if sys.argv[2] == "new":
        d["rows"].append({"id": sys.argv[3], "where": sys.argv[4], "kind": sys.argv[5], "ask": sys.argv[6], "status": "Open"})
    else:
        row = next(r for r in d["rows"] if r["id"] == sys.argv[2])
        for kv in sys.argv[3:]:
            k, v = kv.split("=", 1); row[k] = v
    save("decisions.json", d)
print(now)
