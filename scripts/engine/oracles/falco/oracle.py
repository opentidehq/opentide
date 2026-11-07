#!/usr/bin/env python3
"""Falco oracle: the engine's verdicts against `falco --validate`, case by case.

Each case is one Falco rule: a condition, optional output, exceptions, the
macros and lists it defines, or a tuning (`append_to_rule`). The case becomes

- a Falco rules file: its lists and macros as real `- list:` / `- macro:`
  items, then the rule, or an `override: append` of a Falco default rule. Falco
  validates it with the three default rules files loaded first, so
  default macros and lists resolve and Falco expands the block's own lists and
  macros itself;
- an opentide rule with the same block under `configurations.sysdig`, which
  `opentide-lsp analyze` checks.

Falco runs once per case (a load failure carries over to later files in one
run), all in one container, as many cases at once as there are CPUs. A case agrees when Falco loads it exactly when the
engine reports no `falco_*` or `sysdig_*` error, and when each mapped Falco warning
(`LOAD_NO_EVTTYPE`, ...) is reported by the engine and the reverse. Engine
warnings Falco cannot know (a field of an unknown plugin, newer syntax, a
macro the tenant may define) are listed, not failed.

Corpora: crates/testdata/oracles/falco/cases.yaml (every row of docs/engine/FALCO.md) and
the Falco default rules' syscall conditions with their broken twins
(crates/testdata/conformance/external/falco/syscall). Plugin sources (k8s_audit,
aws_cloudtrail) need their plugin libraries, which the image does not ship.

Usage:
    python scripts/engine/oracles/falco/oracle.py --rules <falcosecurity/rules checkout> \\
        --docker falcosecurity/falco:0.45.2 [--report out.json]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[4]
CASES = ROOT / "crates" / "testdata" / "oracles" / "falco" / "cases.yaml"
DEFAULT_CONDITIONS = ROOT / "crates" / "testdata" / "conformance" / "external" / "falco" / "syscall"

#: The Falco default rules files, in the order Falco's own configuration loads them.
#: The engine's macro, list, and rule catalogue is built from the same files.
DEFAULT_RULES_FILES = ("falco_rules.yaml", "falco-incubating_rules.yaml", "falco-sandbox_rules.yaml")

#: Intentional, documented differences (docs/engine/FALCO.md, "Known differences"). On a
#: Sysdig tenant a name Falco's default rules do not define may be a macro, list,
#: or rule Sysdig manages, so the engine warns where Falco OSS refuses to load.
#: Each entry: (substring of the only Falco error, engine warning code).
DOCUMENTED_DIFFERENCES = (
    ("Undefined macro", "falco_unknown_macro"),
    ("Undefined list", "falco_unknown_list"),
    ("but no rule by that name already exists", "falco_unknown_rule"),
)

#: Falco load warnings and the engine code that reports the same condition.
WARNING_MAP = {
    "LOAD_NO_EVTTYPE": "falco_no_evttype",
    "LOAD_EXCEPTION_NAME_NOT_UNIQUE": "falco_exception",
    "LOAD_DEPRECATED_ITEM": "falco_deprecated_field",
}
#: Engine warnings that depend on the agent or tenant: Falco has no view of them.
AGENT_WARNINGS = {
    "falco_unknown_macro",
    "falco_unknown_list",
    "falco_unknown_source",
    "falco_newer_syntax",
}


def falco_items(case: dict[str, Any], name: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for lst in case.get("lists", []):
        items.append({"list": lst["name"], "items": lst["items"]})
    for macro in case.get("macros", []):
        items.append({"macro": macro["name"], "condition": macro["condition"]})
    if "append_to_rule" in case:
        rule: dict[str, Any] = {"rule": case["append_to_rule"]}
        override = {}
        if "condition" in case:
            rule["condition"] = case["condition"]
            override["condition"] = "append"
        if "exceptions" in case:
            rule["exceptions"] = case["exceptions"]
            override["exceptions"] = "append"
        rule["override"] = override
    else:
        rule = {
            "rule": name,
            "desc": "opentide oracle",
            "condition": case["condition"],
            "output": case.get("output", "opentide oracle"),
            "priority": "WARNING",
            "source": case.get("source", "syscall"),
        }
        if "exceptions" in case:
            rule["exceptions"] = case["exceptions"]
    items.append(rule)
    return items


def tide_rule(case: dict[str, Any], index: int) -> dict[str, Any]:
    block: dict[str, Any] = {"enabled": True, "schema": "platform::sysdig::1.0", "status": "STAGING"}
    for key in ("append_to_rule", "condition", "source", "output", "exceptions", "macros", "lists"):
        if key in case:
            block[key] = case[key]
    return {
        "name": f"Oracle {case['id']}",
        "metadata": {
            "uuid": f"00000000-0000-4000-8000-{index:012d}",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-11-03",
            "modified": "2026-11-03",
            "tlp": "clear",
            "author": "opentide oracle",
            "organisation": {"uuid": "5f3c2a10-7b6e-4c1d-9a8f-2e4b6d0c1a73", "name": "oracle"},
        },
        "description": "Falco oracle case.",
        "response": {"alert_severity": "Medium"},
        "configurations": {"sysdig": block},
    }


def run_falco(image: str, rules: pathlib.Path, scratch: pathlib.Path, ids: list[str]) -> dict[str, Any]:
    defaults = ""
    for name in DEFAULT_RULES_FILES:
        (scratch / name).write_bytes((rules / "rules" / name).read_bytes())
        defaults += f" -V /w/{name}"
    # One Falco process per case, as many at once as there are CPUs: each loads
    # the default rules first, which is most of its time. Each case's output goes
    # to its own file, printed in case order once all are done. The image (Wolfi)
    # has xargs but no nproc, so the count comes from here.
    script = scratch / "run.sh"
    script.write_text(
        "mkdir -p /tmp/out\n"
        f'xargs -n 1 -P "$JOBS" sh -c \'falco -o json_output=true{defaults} -V "/w/falco/$1.yaml" '
        "> \"/tmp/out/$1\" 2>/dev/null; exit 0' _ < /w/ids.txt\n"
        "for id in $(cat /w/ids.txt); do\n"
        '  printf "@@%s\\n" "$id"\n'
        '  cat "/tmp/out/$id"\n'
        '  printf "\\n"\n'
        "done\n",
        encoding="utf-8",
    )
    (scratch / "ids.txt").write_text("\n".join(ids) + "\n", encoding="utf-8")
    jobs = str(os.cpu_count() or 1)
    out = subprocess.run(
        ["docker", "run", "--rm", "-e", f"JOBS={jobs}", "-v", f"{scratch}:/w:ro", "--entrypoint", "sh", image, "/w/run.sh"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    results: dict[str, Any] = {}
    for chunk in out.split("@@")[1:]:
        head, _, body = chunk.partition("\n")
        line = next((ln for ln in body.splitlines() if ln.startswith("{")), None)
        if line is None:
            results[head] = {"successful": False, "errors": [{"code": "NO_OUTPUT", "message": body.strip()}], "warnings": []}
            continue
        loaded = json.loads(line)["falco_load_results"]
        mine = next(r for r in loaded if r["name"].endswith(f"/{head}.yaml"))
        # A failure in the default rules (never expected) counts against the case.
        results[head] = {
            "successful": all(r["successful"] for r in loaded),
            "errors": [{"code": e["code"], "message": e["message"]} for r in loaded for e in r["errors"]],
            "warnings": [{"code": w["code"], "message": w["message"]} for w in mine["warnings"]],
        }
    return results


def run_engine(binary: pathlib.Path, path: pathlib.Path) -> list[dict[str, Any]]:
    out = subprocess.run([str(binary), "analyze", str(path)], check=True, capture_output=True, text=True).stdout
    # The Falco checks and the block's constraint codes (sysdig-1.0): both are
    # what the engine reports about the rule Falco is given.
    return [d for d in json.loads(out) if d["code"].startswith(("falco_", "sysdig_"))]


def _documented(theirs: dict[str, Any], our_errors: list[str], our_warnings: list[str]) -> str | None:
    """The documented difference that explains a verdict mismatch, if exactly one does."""
    if theirs["successful"] or our_errors or len(theirs["errors"]) != 1:
        return None
    message = theirs["errors"][0]["message"]
    for needle, code in DOCUMENTED_DIFFERENCES:
        if needle in message and code in our_warnings:
            return code
    return None


def load_cases() -> list[dict[str, Any]]:
    cases = list(yaml.safe_load(CASES.read_text(encoding="utf-8")))
    for path in sorted(DEFAULT_CONDITIONS.glob("*.falco")):
        cases.append({"id": f"default:{path.stem}", "condition": path.read_text(encoding="utf-8").strip()})
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--rules", type=pathlib.Path, required=True, help="falcosecurity/rules checkout")
    parser.add_argument("--docker", required=True, help="Falco image, e.g. falcosecurity/falco:0.45.2")
    parser.add_argument("--report", type=pathlib.Path, help="write every verdict as JSON")
    parser.add_argument("--only", help="run only the cases whose id contains this text")
    args = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "-p", "opentide-lsp"], cwd=ROOT, check=True)
    binary = ROOT / "target" / "debug" / "opentide-lsp"
    cases = [c for c in load_cases() if not args.only or args.only in c["id"]]
    with tempfile.TemporaryDirectory() as tmp:
        scratch = pathlib.Path(tmp)
        (scratch / "falco").mkdir()
        rules_dir = scratch / "objects" / "rules"
        rules_dir.mkdir(parents=True)
        ids = []
        for index, case in enumerate(cases):
            fid = f"c{index:04d}"
            ids.append(fid)
            case["_fid"] = fid
            text = yaml.safe_dump(falco_items(case, f"opentide oracle {case['id']}"), sort_keys=False, width=10_000)
            (scratch / "falco" / f"{fid}.yaml").write_text(text, encoding="utf-8")
            tide = yaml.safe_dump(tide_rule(case, index), sort_keys=False, width=10_000)
            (rules_dir / f"{fid}.yaml").write_text(tide, encoding="utf-8")
        falco = run_falco(args.docker, args.rules, scratch, ids)
        # One `analyze` process per case, independent of each other: run them at once.
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
            engine = dict(zip(ids, pool.map(lambda fid: run_engine(binary, rules_dir / f"{fid}.yaml"), ids)))
        report = []
        disagreements = 0
        for case in cases:
            theirs = falco[case["_fid"]]
            ours = engine[case["_fid"]]
            our_errors = sorted({d["code"] for d in ours if d["severity"] == "error"})
            our_warnings = sorted({d["code"] for d in ours if d["severity"] == "warning"})
            falco_warnings = sorted({w["code"] for w in theirs["warnings"]})
            problems = []
            documented = None
            if theirs["successful"] == bool(our_errors):
                documented = _documented(theirs, our_errors, our_warnings)
                if documented is None:
                    problems.append("verdict")
            # A case may require engine warnings Falco has no code for.
            for code in case.get("engine_warnings", []):
                if code not in our_warnings:
                    problems.append(f"missing engine warning {code}")
            for code, engine_code in WARNING_MAP.items():
                if theirs["successful"] and (code in falco_warnings) != (engine_code in our_warnings):
                    problems.append(f"warning {code}/{engine_code}")
            disagreements += bool(problems)
            report.append(
                {
                    "id": case["id"],
                    "falco": {"loaded": theirs["successful"], "errors": theirs["errors"], "warnings": theirs["warnings"]},
                    "engine": {"errors": our_errors, "warnings": our_warnings,
                               "messages": [f"{d['code']}: {d['message']}" for d in ours]},
                    "agrees": not problems,
                    "documented_difference": documented,
                    "problems": problems,
                }
            )
    for row in report:
        if not row["agrees"]:
            print(f"DISAGREE {row['id']}: {row['problems']}", file=sys.stderr)
            print(f"  falco: loaded={row['falco']['loaded']} {[e['message'] for e in row['falco']['errors']]} "
                  f"{[w['code'] for w in row['falco']['warnings']]}", file=sys.stderr)
            print(f"  engine: {row['engine']['messages']}", file=sys.stderr)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    loaded = sum(r["falco"]["loaded"] for r in report)
    documented = [r for r in report if r["documented_difference"]]
    for row in documented:
        print(f"documented difference {row['id']}: {row['documented_difference']}")
    print(f"{len(report)} cases ({loaded} Falco loads, {len(report) - loaded} it refuses), "
          f"{len(report) - disagreements} agree ({len(documented)} documented differences), "
          f"{disagreements} disagree")
    return 1 if disagreements else 0


if __name__ == "__main__":
    raise SystemExit(main())
