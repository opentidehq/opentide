#!/usr/bin/env python3
"""Benchmark registry index build and validation wall times."""

from __future__ import annotations

import argparse
import shutil
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from opentide.core.io import yaml_loader_name  # noqa: E402
from opentide.deployment.git_backend import rust_extensions_available  # noqa: E402


def _write_synthetic_rules(target_dir: Path, count: int) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    template = """\
name: Bench rule {index}
description: Synthetic benchmark rule for dependency stack evaluation.
status: STAGING
severity: Medium
techniques:
  - T1059
metadata:
  uuid: {uuid}
  schema: rule::1.0
  version: 1
  created: "2026-01-01T00:00:00Z"
  modified: "2026-01-01T00:00:00Z"
  tlp: clear
platforms: {{}}
"""
    for index in range(count):
        rule_uuid = str(uuid.uuid4())
        path = target_dir / f"bench-rule-{index:04d}.yaml"
        path.write_text(
            template.format(index=index, uuid=rule_uuid),
            encoding="utf-8",
        )


def _prepare_workspace(tmp: Path, rule_count: int) -> Path:
    corpus = ROOT / "tests/fixtures/tide_corpus/current"
    workspace = tmp / "bench-workspace"
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(corpus, workspace)
    rules_dir = workspace / "Objects/Detection Rules"
    _write_synthetic_rules(rules_dir, rule_count)
    return workspace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objects", type=int, default=50, help="Synthetic rule count")
    parser.add_argument("--validate", action="store_true", help="Run full validation")
    args = parser.parse_args()

    import tempfile

    from opentide.core.index_manager import IndexManager
    from opentide.validation.session import run_validation

    print(f"yaml_loader={yaml_loader_name()}")
    print(f"dulwich_rust={rust_extensions_available()}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        workspace = _prepare_workspace(Path(tmp_dir), args.objects)
        import os

        os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(workspace)
        os.environ["OPENTIDE_REPO_ROOT"] = str(workspace)

        IndexManager._cache = None  # noqa: SLF001

        started = time.perf_counter()
        IndexManager.load()
        index_seconds = time.perf_counter() - started
        print(f"index_build_s={index_seconds:.3f}")

        if args.validate:
            started = time.perf_counter()
            report = run_validation()
            validate_seconds = time.perf_counter() - started
            print(
                f"validate_s={validate_seconds:.3f} "
                f"ok={report.ok} objects_checked={report.stats.get('objects_checked', 0)}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
