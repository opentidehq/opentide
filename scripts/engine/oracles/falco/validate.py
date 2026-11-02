#!/usr/bin/env python3
"""Falco oracle: compare the engine's Falco verdicts with `falco --validate`.

Every condition in testdata/conformance/external/falco/syscall/ (the Falco
default rules, unmodified, and their `.broken.` twins) is wrapped in a rule
and validated by Falco together with the default rules file, so the default
macros and lists resolve. Falco accepts a condition when validation exits 0.
Ours rejects it when `opentide-lsp analyze` reports `falco_parse_error`. A
public condition either side rejects, or a broken twin either side accepts,
is a disagreement and fails the run.

Only the `syscall` source is compared: the plugin sources need their plugin
libraries loaded, which the Falco image does not configure.

The reference is the Falco binary, never shipped. Point --falco at a local
binary, or --docker at an image (`falcosecurity/falco:0.41.3`), which runs
`falco --validate` with the files mounted. The sandbox that wrote this
engine reaches neither (download.falco.org and the Docker daemon are not
available there); see scripts/oracles/README.md.

Usage:
    python scripts/oracles/falco/validate.py --rules ../falcosecurity-rules \\
        [--falco falco | --docker falcosecurity/falco:0.41.3]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
CORPUS = ROOT / "testdata" / "conformance" / "external" / "falco" / "syscall"


def falco_accepts(cmd: list[str], rules: pathlib.Path, condition: str, scratch: pathlib.Path) -> bool:
    rule = scratch / "oracle_rule.yaml"
    body = condition.strip().replace("\n", " ")
    rule.write_text(
        "- rule: opentide oracle\n"
        "  desc: oracle\n"
        f"  condition: {json.dumps(body)}\n"
        "  output: oracle\n"
        "  priority: INFORMATIONAL\n",
        encoding="utf-8",
    )
    defaults = scratch / "falco_rules.yaml"
    shutil.copyfile(rules / "rules" / "falco_rules.yaml", defaults)
    run = subprocess.run(
        [*cmd, "--validate", str(defaults), "--validate", str(rule)],
        capture_output=True,
        text=True,
    )
    return run.returncode == 0


def ours_accepts(binary: pathlib.Path, path: pathlib.Path) -> bool:
    out = subprocess.run(
        [str(binary), "analyze", str(path), "--language", "falco"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return not any(d["code"] == "falco_parse_error" for d in json.loads(out))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--rules", type=pathlib.Path, required=True, help="falcosecurity/rules checkout")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--falco", help="falco binary")
    group.add_argument("--docker", help="Falco image, e.g. falcosecurity/falco:0.41.3")
    args = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "-p", "opentide-lsp"], cwd=ROOT, check=True)
    binary = ROOT / "target" / "debug" / "opentide-lsp"
    with tempfile.TemporaryDirectory() as tmp:
        scratch = pathlib.Path(tmp)
        if args.falco:
            cmd = [args.falco]
        else:
            cmd = ["docker", "run", "--rm", "-v", f"{scratch}:{scratch}", args.docker, "falco"]
        disagreements = []
        files = sorted(CORPUS.glob("*.falco"))
        for path in files:
            broken = ".broken." in path.name
            theirs = falco_accepts(cmd, args.rules, path.read_text(encoding="utf-8"), scratch)
            mine = ours_accepts(binary, path)
            if theirs != mine or theirs == broken:
                disagreements.append(f"{path.relative_to(ROOT)}: falco={theirs} ours={mine}")
    for line in disagreements:
        print(line, file=sys.stderr)
    print(f"{len(files)} conditions compared, {len(disagreements)} disagreements")
    return 1 if disagreements else 0


if __name__ == "__main__":
    raise SystemExit(main())
