"""What the oracle (the frozen Python CLI) says about the object models.

Run by `cargo xtask schema diff --against python` with the oracle's
interpreter, isolated (`python -I probe.py COMMAND ...`):

- `schemas RESULT`: every object model's `model_json_schema(by_alias=True)`,
  by class name, and the registry's schema identifiers;
- `objects REPO RESULT`: `opentide --json --repo REPO validate`, run in this
  process, and every object file of the workspace with its family
  (`opentide.analysis.object_files`, by the folder `paths.toml` gives it).

Standard library and the oracle only; no output on stdout is relied on.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import sys
from pathlib import Path

MODELS = {
    "Organisation": "opentide.models.metadata",
    "ObjectMetadata": "opentide.models.metadata",
    "RuleMetadata": "opentide.models.metadata",
    "ObjectReferences": "opentide.models.metadata",
    "ResponseSearch": "opentide.models.response",
    "ResponseProcedure": "opentide.models.response",
    "RuleResponse": "opentide.models.response",
    "ThreatActor": "opentide.models.threat",
    "ThreatBody": "opentide.models.threat",
    "ThreatVector": "opentide.models.threat",
    "SignalData": "opentide.models.objective",
    "ExternalDetector": "opentide.models.objective",
    "DetectionExample": "opentide.models.objective",
    "DetectionSignal": "opentide.models.objective",
    "ObjectiveComposition": "opentide.models.objective",
    "ObjectiveBody": "opentide.models.objective",
    "DetectionObjective": "opentide.models.objective",
    "RuleConfigurations": "opentide.models.platform",
    "SentinelConfig": "opentide.models.platform",
    "DefenderConfig": "opentide.models.platform",
    "SplunkConfig": "opentide.models.platform",
    "SentinelOneConfig": "opentide.models.platform",
    "CrowdstrikeConfig": "opentide.models.platform",
    "HarfangLabConfig": "opentide.models.platform",
    "CarbonBlackConfig": "opentide.models.platform",
    "ElasticConfig": "opentide.models.platform",
    "SysdigConfig": "opentide.models.platform",
    "DetectionRule": "opentide.models.rule",
    "DetectionRule_v1_1": "opentide.models.rule",
}


def schemas(result: str) -> None:
    from opentide.models.schema_registry import registered_identifiers

    out = {}
    for name, module in MODELS.items():
        model = getattr(importlib.import_module(module), name)
        out[name] = model.model_json_schema(by_alias=True)
    with open(result, "w", encoding="utf-8") as handle:
        json.dump({"registered": registered_identifiers(), "schemas": out}, handle)


def objects(repo: str, result: str) -> None:
    from opentide.cli import main as cli

    sys.argv = ["opentide", "--json", "--repo", repo, "validate"]
    out = io.StringIO()
    exit_code = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            cli()
        except SystemExit as stop:
            exit_code = stop.code

    from opentide.registry.catalogue import catalogue_files
    from opentide.registry.paths import resolve_workspace_paths

    root = Path(repo).resolve()
    paths = resolve_workspace_paths(workspace=root)
    files = []
    for family in ("threat", "objective", "rule"):
        folder = paths.get(family)
        if folder is not None and Path(folder).is_dir():
            for path in catalogue_files(Path(folder)):
                relative = Path(path).resolve().relative_to(root).as_posix()
                files.append({"path": relative, "family": family})
    with open(result, "w", encoding="utf-8") as handle:
        json.dump(
            {"exit_code": exit_code, "report": json.loads(out.getvalue()), "objects": files},
            handle,
        )


def main() -> int:
    command = sys.argv[1]
    if command == "schemas":
        schemas(sys.argv[2])
    elif command == "objects":
        objects(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit(f"unknown command {command!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
