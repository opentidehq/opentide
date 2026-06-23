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


def test_no_legacy_root_directories() -> None:
    present = {p.name for p in ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")}
    assert FORBIDDEN_ROOT_DIRS.isdisjoint(present), present & FORBIDDEN_ROOT_DIRS


def test_required_layout_directories() -> None:
    present = {p.name for p in ROOT.iterdir() if p.is_dir()}
    assert present >= REQUIRED_ROOT_DIRS


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
