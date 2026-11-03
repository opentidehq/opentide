"""Merge Code Quality reports into the one file a GitLab job may declare.

GitLab Runner uploads a ``raw`` report (``artifacts:reports:codequality``)
as a single file: a job that lists two fails after its commands passed
(``only one file can be sent as raw``). The generated validate job writes one
report per gate command and merges them in ``after_script``, which also runs
when a command failed, so the merge request still shows the findings::

    python -m opentide.ci.codequality --output opentide-reports/codequality.json \\
        opentide-reports/validate.codequality.json opentide-reports/lint.codequality.json

An input that is missing (the command never ran), empty or not a JSON array
(the command crashed while writing it) is skipped with a note on stderr, so
the merged file is always a valid report, ``[]`` at worst. An issue whose
``fingerprint`` an earlier input already holds is kept once.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _note(message: str) -> None:
    sys.stderr.write(f"opentide codequality: {message}\n")


def read_issues(path: Path) -> list[dict[str, Any]]:
    """The issues of one report, or ``[]`` with a note when it cannot be read."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _note(f"{path} does not exist; skipped")
        return []
    except (OSError, UnicodeDecodeError) as exc:
        _note(f"{path} cannot be read ({exc}); skipped")
        return []
    if not text.strip():
        _note(f"{path} is empty; skipped")
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        _note(f"{path} is not JSON ({exc}); skipped")
        return []
    if not isinstance(document, list):
        _note(f"{path} is not a Code Quality report (a JSON array); skipped")
        return []
    return [issue for issue in document if isinstance(issue, dict)]


def merge_issues(paths: Sequence[Path]) -> list[dict[str, Any]]:
    """Every issue of *paths* in order, each fingerprint once."""
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        for issue in read_issues(path):
            fingerprint = issue.get("fingerprint")
            if isinstance(fingerprint, str):
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
            merged.append(issue)
    return merged


def write_report(output: Path, issues: list[dict[str, Any]]) -> None:
    """Write *issues* to *output* atomically, so a reader never sees half a file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(issues, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, output)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m opentide.ci.codequality",
        description="Merge GitLab Code Quality reports into one file.",
    )
    parser.add_argument("--output", required=True, type=Path, help="The merged report")
    parser.add_argument("inputs", nargs="+", type=Path, help="Reports to merge, in order")
    args = parser.parse_args(argv)
    issues = merge_issues(args.inputs)
    try:
        write_report(args.output, issues)
    except OSError as exc:
        _note(f"cannot write {args.output} ({exc})")
        return 1
    _note(f"{len(issues)} issue(s) from {len(args.inputs)} report(s) in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
