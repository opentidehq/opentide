#!/usr/bin/env python3
"""Datadog oracle: the engine's verdicts against VRL's Datadog search grammar, query by query.

VRL (vectordotdev/vrl, MPL-2.0) is the library behind Datadog's Observability Pipelines; its
``src/datadog/search/grammar.pest`` is the only published grammar of a Datadog search syntax
(docs/internal/rfc-datadog-cloud-siem.md, section 11). It is the pipelines' dialect, not log
search's, so this is an accept-or-reject differential, never a tree comparison: VRL's grammar
has no precedence, and what it accepts is not always what log search means.

The grammar is fetched at a pinned commit and checked against its SHA-256 (``.cache/``, not
committed), then compiled with pest into a small tool (``Cargo.toml`` here, outside the
workspace). Nothing VRL-derived ships.

Corpus:

- ``crates/testdata/conformance/external/datadog/published.jsonl``: Datadog's 2,895 published
  queries, each as ``published.jsonl#<line>``;
- ``crates/testdata/corpus/datadog/*`` (the ``#`` tag line removed, as corpus_gate.rs does).

Ours rejects a query when ``opentide-lsp analyze --language datadog`` reports an error-severity
``datadog_*`` diagnostic (profile ``search``: the profiles differ only in warnings). VRL rejects it
when ``queryroot`` does not parse the whole text. A query where they differ fails unless a
``[[datadog]]`` entry of ``crates/testdata/oracles/exceptions.toml`` lists it in ``paths``, and a
listed path that agrees fails as stale.

Usage:
    python scripts/engine/oracles/datadog/oracle.py [--binary target/debug/opentide-lsp] \\
        [--report report.json]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

import tomllib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PUBLISHED = ROOT / "crates/testdata/conformance/external/datadog/published.jsonl"
CORPUS = ROOT / "crates/testdata/corpus/datadog"
EXCEPTIONS = ROOT / "crates/testdata/oracles/exceptions.toml"

#: vectordotdev/vrl v0.39.0. The grammar is the same at v0.29.0 (2025) and v0.39.0.
VRL_COMMIT = "1e3e2e8ad4d3ec70ee247fbf85a2af8a45d869ea"
GRAMMAR_PATH = "src/datadog/search/grammar.pest"
GRAMMAR_URL = f"https://raw.githubusercontent.com/vectordotdev/vrl/{VRL_COMMIT}/{GRAMMAR_PATH}"
GRAMMAR_SHA256 = "c1171e63918f8427da35e35b778e7a514dcf92c54292a70c7f1ee0995783fa55"
CACHE = HERE / ".cache"


def fetch_grammar() -> None:
    """``.cache/grammar.pest`` at the pinned commit, its hash checked."""
    target = CACHE / "grammar.pest"
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == GRAMMAR_SHA256:
        return
    CACHE.mkdir(exist_ok=True)
    with urllib.request.urlopen(GRAMMAR_URL, timeout=60) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != GRAMMAR_SHA256:
        raise SystemExit(f"{GRAMMAR_URL}: SHA-256 {digest}, expected {GRAMMAR_SHA256}")
    target.write_bytes(data)


def build_oracle() -> pathlib.Path:
    """The pest tool, built with its lock file."""
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--manifest-path", str(HERE / "Cargo.toml")],
        check=True,
    )
    return HERE / "target" / "release" / "opentide-datadog-vrl-oracle"


def corpus() -> list[tuple[str, str]]:
    """``(path, query)`` for every query compared."""
    out: list[tuple[str, str]] = []
    rel = PUBLISHED.relative_to(ROOT).as_posix()
    for number, line in enumerate(PUBLISHED.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            out.append((f"{rel}#{number}", json.loads(line)["query"]))
    for path in sorted(CORPUS.iterdir()):
        text = path.read_text(encoding="utf-8")
        body = "\n".join(text.split("\n")[1:]).rstrip("\n")
        out.append((path.relative_to(ROOT).as_posix(), body))
    return out


def vrl_verdicts(oracle: pathlib.Path, queries: list[str]) -> list[bool]:
    """Whether VRL accepts each query."""
    stdin = "".join(json.dumps(q) + "\n" for q in queries)
    done = subprocess.run([str(oracle)], input=stdin, capture_output=True, text=True, check=True)
    verdicts = done.stdout.splitlines()
    if len(verdicts) != len(queries) or "error" in verdicts:
        raise SystemExit("the VRL oracle did not answer every query")
    return [v == "accept" for v in verdicts]


def ours(binary: pathlib.Path, query: str) -> bool:
    """Whether the engine accepts the query: no error-severity diagnostic."""
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
    diagnostics = json.loads(done.stdout)
    return not any(d.get("severity") == "error" for d in diagnostics)


def listed() -> dict[str, str]:
    """The paths of the ``[[datadog]]`` entries, each with its entry's id."""
    doc = tomllib.loads(EXCEPTIONS.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for entry in doc.get("datadog", []):
        if not entry.get("reason") or not entry.get("id"):
            raise SystemExit(f"[[datadog]] {entry.get('id')}: an id and a reason are required")
        for path in entry.get("paths", []):
            out[path] = entry["id"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", type=pathlib.Path, default=ROOT / "target/debug/opentide-lsp")
    ap.add_argument("--report", type=pathlib.Path)
    args = ap.parse_args()
    fetch_grammar()
    oracle = build_oracle()
    cases = corpus()
    vrl = vrl_verdicts(oracle, [q for _, q in cases])
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        mine = list(pool.map(lambda case: ours(args.binary, case[1]), cases))
    exceptions = listed()
    disagreements = []
    for (path, query), theirs, own in zip(cases, vrl, mine, strict=True):
        if theirs != own:
            disagreements.append({"path": path, "query": query, "vrl": theirs, "ours": own})
    unlisted = [d for d in disagreements if d["path"] not in exceptions]
    disagreeing = {d["path"] for d in disagreements}
    stale = sorted(p for p in exceptions if p not in disagreeing)
    agree = len(cases) - len(disagreements)
    print(
        f"datadog: {len(cases)} queries, {agree} agree with VRL, {len(disagreements)} listed or not"
    )
    for d in unlisted:
        side = "VRL accepts, ours rejects" if d["vrl"] else "VRL rejects, ours accepts"
        print(f"  unlisted: {d['path']} ({side}): {d['query']!r}")
    for path in stale:
        print(f"  stale: {path} ({exceptions[path]}) agrees now: delete it from exceptions.toml")
    if args.report:
        args.report.write_text(
            json.dumps(
                {"cases": len(cases), "agree": agree, "disagreements": disagreements}, indent=2
            ),
            encoding="utf-8",
        )
    if unlisted:
        print("\nTOML to start from:")
        print('[[datadog]]\nid = "TODO"\nreason = "TODO"\npaths = [')
        for d in unlisted:
            print(f'  "{d["path"]}",')
        print("]")
    return 1 if unlisted or stale else 0


if __name__ == "__main__":
    sys.exit(main())
