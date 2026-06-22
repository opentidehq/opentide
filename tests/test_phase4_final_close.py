"""Phase 4 final close — loaders, pydantic templates, generation artifact gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from opentide.generation.artifact_gate import (
    TIDE_WORKSPACE_DIR,
    collect_generation_checksums,
    load_checksum_baseline,
    tide_instance_root,
    verify_generation_checksums,
)
from opentide.generation.pydantic_templates import (
    CORE_TEMPLATE_MODELS,
    core_metaschema_path,
    core_template_model_keys,
    load_core_template_source,
)
from opentide.generation.template_renderer import run as template_renderer_run
from opentide.loading.compat import ObjectLoader, TideLoader
from opentide.loading.objective_loader import load_objective_from_dict, load_signal_from_dict
from opentide.models.objective import DetectionObjective, DetectionSignal

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_BASELINE = ROOT / "tests/fixtures/generation/artifact_checksums.json"
TIDE_WORKSPACE = ROOT / TIDE_WORKSPACE_DIR


def _metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "objective::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


def _signal_payload() -> dict[str, Any]:
    return {
        "name": "Signal",
        "uuid": "00000000-0000-4000-8000-000000000099",
        "description": "sig",
        "severity": "Medium",
        "methodology": "analytics",
        "entities": ["host"],
        "data": {"availability": "Complete", "requirements": "logs"},
    }


def _objective_payload() -> dict[str, Any]:
    return {
        "name": "Objective",
        "metadata": _metadata(),
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "description": "obj",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [_signal_payload()],
        },
    }


@pytest.fixture
def tide_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect tide instance outputs into a repo-local workspace for portable CI."""
    TIDE_WORKSPACE.mkdir(parents=True, exist_ok=True)
    for rel in (
        "Schemas",
        "Schemas/Templates",
        "Schemas/Configurations",
        "Schemas/Indexes",
        "Schemas/Exports",
        "Objects/Threat Vectors",
        "Objects/Detection Objectives",
        "Objects/Detection Rules",
        "Analytics",
        ".vscode",
    ):
        (TIDE_WORKSPACE / rel).mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(TIDE_WORKSPACE.resolve()))
    return TIDE_WORKSPACE


def test_legacy_loader_modules_removed() -> None:
    assert not (ROOT / "Engines/modules/loaders/object_loader.py").exists()
    assert not (ROOT / "Engines/modules/loaders/system_loader.py").exists()


def test_load_signal_from_dict_typed() -> None:
    signal = load_signal_from_dict(_signal_payload())
    assert isinstance(signal, DetectionSignal)
    assert signal.data.availability == "Complete"


def test_load_objective_from_dict_typed() -> None:
    objective = load_objective_from_dict(_objective_payload())
    assert isinstance(objective, DetectionObjective)
    assert len(objective.objective.signals) == 1


def test_object_loader_compat_shim_delegates() -> None:
    assert ObjectLoader.load_signal is load_signal_from_dict
    assert ObjectLoader.load_objective is load_objective_from_dict
    assert TideLoader.load_dom is load_objective_from_dict


def test_core_template_models_match_schema_models() -> None:
    assert set(CORE_TEMPLATE_MODELS) == {"mdr", "dom", "tvm"}


def test_load_core_template_source_returns_properties() -> None:
    source = load_core_template_source("mdr")
    assert "properties" in source
    assert "required" in source


def test_core_metaschema_paths_exist() -> None:
    for key in core_template_model_keys():
        assert core_metaschema_path(key).is_file()


def test_template_renderer_uses_pydantic_pipeline() -> None:
    source = (ROOT / "src/opentide/generation/template_renderer.py").read_text()
    assert "pydantic_templates" in source
    assert "generate_core_template" in source
    assert "def gen_template" not in source


def test_pydantic_templates_module_has_engine() -> None:
    source = (ROOT / "src/opentide/generation/pydantic_templates.py").read_text()
    assert "template_engine" in source
    assert "CORE_TEMPLATE_MODELS" in source


def test_template_renderer_run_smoke() -> None:
    template_renderer_run()


def test_tide_instance_root_uses_workspace_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(TIDE_WORKSPACE.resolve()))
    assert tide_instance_root(ROOT) == TIDE_WORKSPACE.resolve()


def _run_generate_py() -> None:
    env = {**os.environ, "TERM_PROGRAM": "vscode"}
    if workspace := os.environ.get("OPENTIDE_TIDE_WORKSPACE"):
        env["OPENTIDE_TIDE_WORKSPACE"] = workspace
    result = subprocess.run(
        [sys.executable, "Orchestration/generate.py"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"generate.py failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")


def test_generate_py_artifact_byte_checksum_gate(tide_workspace: Path) -> None:
    """CI gate: generate.py outputs must remain byte-stable."""
    del tide_workspace  # fixture activates path patching
    if not ARTIFACT_BASELINE.is_file():
        pytest.fail("Missing generation artifact baseline checksum file")
    expected = load_checksum_baseline(ARTIFACT_BASELINE)
    _run_generate_py()
    verify_generation_checksums(expected, repo_root=ROOT)


def test_collect_generation_checksums_matches_baseline_file(tide_workspace: Path) -> None:
    del tide_workspace
    expected = json.loads(ARTIFACT_BASELINE.read_text(encoding="utf-8"))
    actual = collect_generation_checksums(ROOT)
    assert set(actual) == set(expected)
