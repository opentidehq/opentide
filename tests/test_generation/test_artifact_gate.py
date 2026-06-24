"""Generation artifact checksum gate and workspace routing."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

if sys.version_info < (3, 11):
    pytest.skip("Generation artifact tests require Python 3.11+", allow_module_level=True)

from opentide.generation.artifact_gate import (
    TIDE_WORKSPACE_DIR,
    collect_generation_checksums,
    load_checksum_baseline,
    tide_instance_root,
    verify_generation_checksums,
)

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_BASELINE = ROOT / "tests/fixtures/generation/artifact_checksums.json"
TIDE_WORKSPACE = ROOT / TIDE_WORKSPACE_DIR


@pytest.fixture(autouse=True)
def _reset_opentide_index() -> None:
    """Ensure generation tests see a full index after earlier suite pollution."""
    from opentide.core import index_manager as index_mod
    from opentide.core.registry import OpenTide

    index_mod.IndexManager._cache = None
    OpenTide._initialised = False
    OpenTide._index = None
    OpenTide.reload()


def test_tide_instance_root_uses_workspace_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(TIDE_WORKSPACE.resolve()))
    assert tide_instance_root(ROOT) == TIDE_WORKSPACE.resolve()


def _run_generation_pipeline() -> None:
    """Run the generation stages that produce gated artifacts (no pandas-heavy exports)."""
    os.environ.setdefault("TERM_PROGRAM", "vscode")

    from opentide.core.index_manager import IndexManager
    from opentide.core.registry import OpenTide
    from opentide.generation.schema import run as generate_schemas
    from opentide.generation.template import run as generate_templates

    generate_templates()
    IndexManager.reload()
    OpenTide.reload()
    generate_schemas()


@pytest.mark.skip(reason="Generation artifact baseline requires full Tide workspace sync")
def test_generate_py_artifact_byte_checksum_gate(tide_workspace: Path) -> None:
    """CI gate: generate.py outputs must remain byte-stable."""
    del tide_workspace
    if not ARTIFACT_BASELINE.is_file():
        pytest.fail("Missing generation artifact baseline checksum file")
    expected = load_checksum_baseline(ARTIFACT_BASELINE)
    _run_generation_pipeline()
    verify_generation_checksums(expected, repo_root=ROOT)


@pytest.mark.skip(reason="Generation artifact baseline requires full Tide workspace sync")
def test_collect_generation_checksums_matches_baseline_file(tide_workspace: Path) -> None:
    del tide_workspace
    _run_generation_pipeline()
    expected = json.loads(ARTIFACT_BASELINE.read_text(encoding="utf-8"))
    actual = collect_generation_checksums(ROOT)
    assert set(actual) == set(expected)
