"""Draft ``tests/golden/APPROVED_DIFFS.toml`` entries from an in-process replay.

``OPENTIDE_REPLAY_DUMP=DIR cargo test -p opentide-cli --test command_goldens``
writes each replayed case's candidate run (normalised stdout, stderr, exit
code and files) under ``DIR/<case id>/``. This script compares each with its
recording under ``tests/golden/cases`` and prints the narrowest entries that
approve the differences, one per distinct difference, its case glob the
cases that share it:

- a JSON document (both sides parse): one ``json:`` entry per node that
  differs: a scalar, an object whose keys differ or are in another order, an
  array of another length;
- text: one ``lines`` entry per block ``difflib`` finds changed, with a line of
  context when the block only adds or only drops lines.

Each entry's ``reason``, ``issue`` and ``changelog`` come from the first rule
of a ``--reasons`` TOML file whose ``match`` (a regular expression) is found
in the entry's oracle or candidate side, or in its case id when the rule
says ``on = "case"``; an entry no rule explains is printed with
``reason = "UNEXPLAINED"`` so a person reads it. Nothing here edits the
ledger: a person reviews the output and pastes it.

Usage::

    python3 scripts/golden/ledger_entries.py DUMP_DIR --reasons REASONS.toml
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import tomllib
from collections import OrderedDict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CASES = REPO / "tests" / "golden" / "cases"


def toml_string(text: str) -> str:
    """A TOML basic string: JSON's escapes, plus DEL, which TOML refuses raw."""
    return json.dumps(text, ensure_ascii=False).replace("\x7f", "\\u007f")


def load_json(data: bytes) -> object | None:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=OrderedDict)
    except (UnicodeDecodeError, ValueError):
        return None


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def pointer_part(key: object) -> str:
    return str(key).replace("~", "~0").replace("/", "~1")


def json_entries(oracle: object, candidate: object, pointer: str = "") -> list[tuple[str, str, str]]:
    """``(pointer, oracle JSON, candidate JSON)`` for each node that differs."""
    if isinstance(oracle, dict) and isinstance(candidate, dict):
        if list(oracle) != list(candidate):
            return [(pointer, compact(oracle), compact(candidate))]
        out: list[tuple[str, str, str]] = []
        for key in oracle:
            out += json_entries(oracle[key], candidate[key], f"{pointer}/{pointer_part(key)}")
        return out
    if isinstance(oracle, list) and isinstance(candidate, list):
        if len(oracle) != len(candidate):
            return [(pointer, compact(oracle), compact(candidate))]
        out = []
        for index, (left, right) in enumerate(zip(oracle, candidate, strict=True)):
            out += json_entries(left, right, f"{pointer}/{index}")
        return out
    if compact(oracle) != compact(candidate) or type(oracle) is not type(candidate):
        return [(pointer, compact(oracle), compact(candidate))]
    return []


def text_entries(oracle: str, candidate: str) -> list[tuple[str, str]]:
    """``(oracle lines, candidate lines)`` for each changed block."""
    left, right = oracle.split("\n"), candidate.split("\n")
    out = []
    matcher = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if i1 == i2 or j1 == j2:
            # Only added or only dropped lines: anchor on the line before.
            if i1 > 0 and j1 > 0:
                i1, j1 = i1 - 1, j1 - 1
            else:
                i2, j2 = i2 + 1, j2 + 1
        out.append(("\n".join(left[i1:i2]), "\n".join(right[j1:j2])))
    return out


def case_glob(ids: list[str]) -> str:
    parts = [case_id.split("/") for case_id in ids]
    return "/".join(
        values[0] if len(set(values)) == 1 else "*" for values in zip(*parts, strict=True)
    )


def targets(case_dir: Path, dump_dir: Path) -> list[tuple[str, bytes, bytes]]:
    out = []
    for stream in ("stdout", "stderr"):
        out.append((stream, (case_dir / stream).read_bytes(), (dump_dir / stream).read_bytes()))
    files = dump_dir / "files"
    if files.is_dir():
        for path in sorted(files.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(files).as_posix()
            recorded = case_dir / "files" / relative
            if recorded.is_file():
                out.append((f"file:{relative.removeprefix('ws/')}", recorded.read_bytes(), path.read_bytes()))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dump", type=Path)
    parser.add_argument("--reasons", type=Path, required=True)
    args = parser.parse_args()
    reasons = tomllib.loads(args.reasons.read_text("utf-8"))["reason"]
    grouped: OrderedDict[tuple[str, str, str, str, str], list[str]] = OrderedDict()
    for exit_file in sorted(args.dump.rglob("exit_code")):
        dump_dir = exit_file.parent
        case_id = dump_dir.relative_to(args.dump).as_posix()
        case_dir = CASES / case_id
        command = tomllib.loads((case_dir / "case.toml").read_text("utf-8"))["command"]
        for target, oracle, candidate in targets(case_dir, dump_dir):
            if oracle == candidate:
                continue
            left, right = load_json(oracle), load_json(candidate)
            if left is not None and right is not None:
                for pointer, old, new in json_entries(left, right):
                    key = (command, target, f"json:{pointer}", old, new)
                    grouped.setdefault(key, []).append(case_id)
                continue
            for old, new in text_entries(oracle.decode("utf-8"), candidate.decode("utf-8")):
                grouped.setdefault((command, target, "lines", old, new), []).append(case_id)
    for (command, target, rule, old, new), ids in grouped.items():
        found = None
        for reason in reasons:
            haystacks = [" ".join(ids)] if reason.get("on") == "case" else [old, new]
            if reason.get("command") not in (None, command):
                continue
            if any(re.search(reason["match"], text) for text in haystacks):
                found = reason
                break
        print("[[diff]]")
        print(f"command = {toml_string(command)}")
        print(f"case = {toml_string(case_glob(ids))}")
        print(f"target = {toml_string(target)}")
        print(f"rule = {toml_string(rule)}")
        print(f"oracle = {toml_string(old)}")
        print(f"candidate = {toml_string(new)}")
        print(f"reason = {toml_string(found['reason'] if found else 'UNEXPLAINED')}")
        print(f"issue = {toml_string(found['issue'] if found else '')}")
        print(f"changelog = {toml_string(found['changelog'] if found else '')}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
