#!/usr/bin/env python3
"""Measure Datadog's default rules, as the Terraform provider's test cassettes record them.

DataDog/terraform-provider-datadog's ``TestAccDatadogSecurityMonitoringDefaultRule_*`` cassettes
(MPL-2.0 files recording Datadog's own rules) hold the API's answers listing the default rules
(``isDefault: true``), with their queries. They are measured, never vendored
(docs/internal/rfc-datadog-cloud-siem.md, section 10): this script reads a local checkout, runs
each distinct query through the engine (profile ``search``: errors only matter here) and through
VRL's grammar (``oracle.py``), and prints what docs/engine/DATADOG.md records.

Usage:
    python scripts/engine/oracles/datadog/default_rules.py \\
        --terraform ../terraform-provider-datadog [--binary target/debug/opentide-lsp]
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import oracle  # noqa: E402 -- the oracle beside this script, once its directory is on the path


def default_rule_queries(checkout: pathlib.Path) -> tuple[int, list[str]]:
    """The number of default rules and their distinct queries, in the order first seen."""
    cassettes = sorted(
        (checkout / "datadog/tests/cassettes").glob(
            "TestAccDatadogSecurityMonitoringDefaultRule_*.yaml"
        )
    )
    if not cassettes:
        raise SystemExit(f"{checkout}: no default-rule cassettes")
    rules: set[str] = set()
    queries: dict[str, None] = {}
    for path in cassettes:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for interaction in document.get("interactions", []):
            body = (interaction.get("response") or {}).get("body") or ""
            try:
                answer = json.loads(body)
            except ValueError:
                continue
            data = answer.get("data") if isinstance(answer, dict) else None
            items = data if isinstance(data, list) else []
            for rule in items:
                if not isinstance(rule, dict) or not rule.get("isDefault"):
                    continue
                rules.add(str(rule.get("id")))
                for query in rule.get("queries") or []:
                    text = query.get("query")
                    if text:
                        queries.setdefault(text, None)
    return len(rules), list(queries)


def codes(binary: pathlib.Path, query: str) -> list[tuple[str, str]]:
    """``(code, severity)`` of each diagnostic the engine reports on ``query``."""
    with tempfile.NamedTemporaryFile("w", suffix=".datadog", encoding="utf-8", delete=False) as f:
        f.write(query)
        name = f.name
    try:
        done = subprocess.run(
            [str(binary), "analyze", "--language", "datadog", name],
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        os.unlink(name)
    return [(d["code"], d["severity"]) for d in json.loads(done.stdout)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--terraform", type=pathlib.Path, required=True)
    ap.add_argument(
        "--binary", type=pathlib.Path, default=oracle.ROOT / "target/debug/opentide-lsp"
    )
    args = ap.parse_args()
    rules, queries = default_rule_queries(args.terraform)
    oracle.fetch_grammar()
    vrl = oracle.vrl_verdicts(oracle.build_oracle(), queries)
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        found = list(pool.map(lambda q: codes(args.binary, q), queries))
    counts: collections.Counter[str] = collections.Counter()
    errors = 0
    disagree = []
    for query, theirs, diagnostics in zip(queries, vrl, found, strict=True):
        counts.update(f"{code} ({severity})" for code, severity in diagnostics)
        rejected = any(severity == "error" for _, severity in diagnostics)
        errors += rejected
        if theirs == rejected:
            disagree.append(query)
    print(f"{rules} default rules, {len(queries)} distinct queries")
    print(f"engine errors: {errors}; agreement with VRL: {len(queries) - len(disagree)}")
    for code, n in sorted(counts.items()):
        print(f"  {code}: {n}")
    for query in disagree:
        print(f"  disagrees with VRL: {query!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
