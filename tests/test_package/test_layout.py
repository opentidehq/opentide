"""Repository layout and bundled configuration sanity checks."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN_ROOT_DIRS = {
    "Configurations",
    "Engines",
    "External",
    "Framework",
    "Orchestration",
    "Pipelines",
}

REQUIRED_ROOT_DIRS = {
    "src",
    "tests",
    "docs",
}

FORBIDDEN_WORKFLOW_TOKENS = (
    "OpenTideHQ/CoreTide",
    "coretide/Orchestration",
    "TIDE_CORE_REPO",
    "Engines/requirements.txt",
)


def test_no_legacy_root_directories() -> None:
    present = {p.name for p in ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")}
    assert FORBIDDEN_ROOT_DIRS.isdisjoint(present), present & FORBIDDEN_ROOT_DIRS


def test_required_layout_directories() -> None:
    present = {p.name for p in ROOT.iterdir() if p.is_dir()}
    assert present >= REQUIRED_ROOT_DIRS


def test_package_workflows_have_no_coretide_dependencies() -> None:
    workflows = ROOT / ".github" / "workflows"
    if not workflows.is_dir():
        return
    for workflow in workflows.glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        for token in FORBIDDEN_WORKFLOW_TOKENS:
            assert token not in text, f"{workflow.name} references legacy CoreTide CI: {token}"


def test_no_legacy_client_pipeline_directory() -> None:
    assert not (ROOT / ".github" / "pipelines").exists()


def test_bundled_global_config_objects() -> None:
    global_toml = ROOT / "src/opentide/data/configurations/global.toml"
    assert global_toml.is_file()
    text = global_toml.read_text(encoding="utf-8")
    assert '"dom"' in text
    assert '"cdm"' not in text
    assert 'objects = [ "tvm", "dom", "mdr" ]' in text
    assert "Framework/Vocabulary" not in text


def test_engines_package_absorbed() -> None:
    assert not (ROOT / "src" / "Engines").exists()
