#!/usr/bin/env python3
"""Smoke-test an installed opentide the way a user meets it.

    python -I scripts/build/smoke_package.py VERSION

Run it with the interpreter of the environment opentide was just installed
into (`pip install` of a wheel or the sdist), from a checkout: publish.yml's
smoke jobs and the Windows on Arm wheel check (build-packages.yml) do, on
Linux, macOS and Windows. Since UC-6.2 the package is the Rust core and a thin
Python layer over it, with pydantic its only dependency. It checks:

- `opentide --version`, the console script beside this interpreter, prints
  VERSION;
- the installed package requires what pyproject.toml declares and nothing
  else, so a wheel that gained or lost a dependency fails here;
- `opentide --json validate` passes on the tide corpus
  (tests/fixtures/tide_corpus/current, copied to a temporary folder in the
  current layout: `.opentide/configurations` and `objects/`), and finds its
  objects and queries;
- the SDK, from the installed package: `Workspace.open` on that copy lists
  its rules and validates it as the command line did, `run_json(["info"])`,
  `opentide.models` (the Rust classes) and `opentide.analysis.check_query`.

The standard library only (Python 3.11 or later, for tomllib), and nothing of
the checkout is imported: `-I` keeps the script's folder off sys.path, and the
package lives under `src/`.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "fixtures" / "tide_corpus" / "current"
#: The legacy folders of the fixture and where the current layout keeps them.
LAYOUT = {
    "Configurations": ".opentide/configurations",
    "Objects/Threat Vectors": "objects/threats",
    "Objects/Detection Objectives": "objects/objectives",
    "Objects/Detection Rules": "objects/rules",
}


def fail(message: str) -> None:
    sys.exit(f"smoke_package: {message}")


def console_script() -> Path:
    """The `opentide` the install put beside this interpreter."""
    name = "opentide.exe" if os.name == "nt" else "opentide"
    script = Path(sys.executable).parent / name
    if not script.is_file():
        fail(f"no console script at {script}")
    return script


def _requirement(text: str) -> str:
    return re.sub(r"\s+", "", text).lower()


def check_requirements() -> list[str]:
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    wanted = sorted(_requirement(r) for r in declared["project"]["dependencies"])
    installed = sorted(_requirement(r) for r in importlib.metadata.requires("opentide") or [])
    if installed != wanted:
        fail(f"opentide requires {installed}, but pyproject.toml declares {wanted}")
    return installed


def materialise(dest: Path) -> Path:
    """The tide corpus in the current workspace layout, copied (no symlinks,
    which Windows refuses without Developer Mode)."""
    for legacy, current in LAYOUT.items():
        shutil.copytree(CORPUS / legacy, dest / current)
    for folder in ("schemas", "templates", "exports", "inflight"):
        (dest / ".opentide" / folder).mkdir(parents=True, exist_ok=True)
    return dest


def run(argv: list[str], cwd: Path) -> str:
    done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        fail(f"{' '.join(argv)} exited {done.returncode}:\n{done.stdout}{done.stderr}")
    return done.stdout


def main(argv: list[str]) -> None:
    if len(argv) != 1:
        sys.exit(__doc__)
    (version,) = argv
    opentide = console_script()

    out = run([str(opentide), "--version"], Path.cwd()).strip()
    if version not in out:
        fail(f"opentide --version printed {out!r}, not {version}")
    print(f"ok   {out}")

    print(f"ok   opentide requires {check_requirements()}")

    with tempfile.TemporaryDirectory() as tmp:
        workspace = materialise(Path(tmp) / "corpus")
        document = json.loads(run([str(opentide), "--json", "validate"], workspace))
        summary = document.get("summary") or {}
        if not document.get("ok") or not summary.get("objects") or not summary.get("queries"):
            fail(f"validate on the tide corpus: {json.dumps(document)[:2000]}")
        objects, queries = summary["objects"], summary["queries"]
        print(f"ok   opentide --json validate: {objects} objects, {queries} queries")

        # The SDK, from the installed package, on the same workspace.
        import opentide
        from opentide import Workspace
        from opentide.analysis import check_query
        from opentide.models import DetectionRule

        installed = Path(opentide.__file__).resolve()
        if ROOT in installed.parents:
            fail(f"opentide was imported from the checkout ({installed})")
        ws = Workspace.open(workspace)
        rules = ws.rules()
        validation = ws.validate()
        if not rules or validation.failed or validation.summary != summary:
            fail(
                f"the SDK: {len(rules)} rules, failed={validation.failed}, "
                f"summary {validation.summary} (the command line's: {summary})"
            )
        info = ws.run_json(["info"])
        if not isinstance(info, dict) or not info.get("ok"):
            fail(f"run_json(['info']) returned {info!r}")
        if not DetectionRule.__module__.startswith("opentide._native"):
            fail(
                f"opentide.models.DetectionRule is {DetectionRule.__module__}'s, not the Rust class"
            )
        codes = [finding.code for finding in check_query("SecurityEvent | wher x", language="kql")]
        if codes != ["kql_unknown_operator"]:
            fail(f"check_query found {codes}")
        print(f"ok   the SDK: {len(rules)} rules, validate() passes, info, models and check_query")
    print(f"PASS: opentide {version} installs and runs")


if __name__ == "__main__":
    main(sys.argv[1:])
