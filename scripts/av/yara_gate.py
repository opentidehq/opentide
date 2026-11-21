#!/usr/bin/env python3
"""Scan release artifacts with public YARA rule sets; fail on a hit not allow-listed (#1743).

    yara_gate.py --signature-base DIR --elastic DIR --allowlist FILE [--report FILE] TREE

TREE is a directory of extracted artifacts (extract.py). The rule sets are the Neo23x0
signature-base `yara/` and Elastic protections-artifacts `yara/` directories, checked out at the
commits `fetch-rules.sh` pins. Each rule file is compiled on its own (a file that needs a module or
an external the CLI does not define is reported and skipped), the ones that compile are bundled, and
every file under TREE is scanned with the bundle.

A hit is `RULE path`. One whose rule is not in the allow-list (`yara-allowlist.toml`: the rule, why
it is noise, who reviewed it, when) fails the gate. Nothing is uploaded: the yara binary runs here.
Exit status: 0 every hit allow-listed (or none), 1 a hit not allow-listed, 2 the gate could not run.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import tomllib
from markers import is_source_member

#: signature-base's rules read these externals.
EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")


def _externals(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    filetype = {".exe": "EXE", ".dll": "DLL", ".pyd": "DLL", ".so": "ELF"}.get(suffix, "")
    values = {
        "filename": path.name,
        "filepath": str(path),
        "extension": suffix,
        "filetype": filetype,
        "owner": "opentide-av-gate",
    }
    args: list[str] = []
    for name in EXTERNALS:
        args += ["-d", f"{name}={values[name]}"]
    return args


def rule_files(*directories: Path) -> list[Path]:
    found: list[Path] = []
    for directory in directories:
        found += sorted(p for p in directory.rglob("*") if p.suffix in {".yar", ".yara"})
    return found


def compile_bundle(files: list[Path], out: Path) -> tuple[list[Path], list[tuple[Path, str]]]:
    """The rule files that compile, bundled into `out`, and those that do not, with why."""
    good: list[Path] = []
    bad: list[tuple[Path, str]] = []
    probe = Path(tempfile.mkdtemp(prefix="yarac-")) / "probe.yarc"
    for file in files:
        result = subprocess.run(
            ["yarac", "-w", *_externals(Path("x.exe")), str(file), str(probe)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            good.append(file)
        else:
            bad.append((file, (result.stderr.strip().splitlines() or ["?"])[-1]))
    subprocess.run(
        ["yarac", "-w", *_externals(Path("x.exe")), *map(str, good), str(out)], check=True
    )
    return good, bad


def in_source_distribution(file: Path, tree: Path) -> bool:
    """Whether `file` is a text source member of an extracted sdist or `.crate` (markers.py)."""
    parts = file.relative_to(tree).parts
    for index, part in enumerate(parts[:-1]):
        if part.endswith((".tar.gz.d", ".crate.d")):
            member = "/".join(parts[index + 1 :])
            return is_source_member(part[: -len(".d")], member)
    return False


def scan(bundle: Path, tree: Path) -> dict[str, list[str]]:
    """`rule -> [paths]` for every file under `tree`."""
    hits: dict[str, list[str]] = defaultdict(list)
    for file in sorted(p for p in tree.rglob("*") if p.is_file()):
        if in_source_distribution(file, tree):
            continue
        result = subprocess.run(
            ["yara", "-C", "-w", *_externals(file), str(bundle), str(file)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 1):
            print(f"yara_gate: yara failed on {file}: {result.stderr.strip()}", file=sys.stderr)
            raise SystemExit(2)
        for line in result.stdout.splitlines():
            rule, _, _path = line.partition(" ")
            if rule:
                hits[rule].append(str(file.relative_to(tree)))
    return hits


def allowed_rules(path: Path) -> dict[str, str]:
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    allowed: dict[str, str] = {}
    for entry in document.get("allow", []):
        rule, reason, reviewed = entry.get("rule"), entry.get("reason"), entry.get("reviewed")
        if not (rule and reason and reviewed):
            raise SystemExit(
                f"yara_gate: {path}: every [[allow]] needs rule, reason and reviewed: {entry}"
            )
        allowed[rule] = reason
    return allowed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--signature-base", type=Path, required=True)
    parser.add_argument("--elastic", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("tree", type=Path)
    args = parser.parse_args(argv)

    files = rule_files(args.signature_base / "yara", args.elastic / "yara")
    if not files or not args.tree.is_dir():
        print("yara_gate: no rule files, or TREE is not a directory", file=sys.stderr)
        return 2
    allowed = allowed_rules(args.allowlist)
    with tempfile.TemporaryDirectory() as scratch:
        bundle = Path(scratch) / "rules.yarc"
        good, bad = compile_bundle(files, bundle)
        hits = scan(bundle, args.tree)
    lines = [
        f"YARA: {len(good)} of {len(files)} rule files compiled ({len(bad)} skipped), "
        f"{sum(len(v) for v in hits.values())} hit(s) in {len(hits)} rule(s)"
    ]
    failing = {rule: paths for rule, paths in hits.items() if rule not in allowed}
    for rule, paths in sorted(hits.items()):
        mark = "allow-listed" if rule in allowed else "NOT ALLOW-LISTED"
        lines.append(f"  {rule}: {mark}, {len(paths)} file(s), e.g. {paths[0]}")
    for file, why in bad:
        lines.append(f"  skipped {file.name}: {why}")
    text = "\n".join(lines)
    print(text)
    if args.report:
        args.report.write_text(text + "\n")
    if failing:
        print(f"yara_gate: {len(failing)} rule(s) hit without being allow-listed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
