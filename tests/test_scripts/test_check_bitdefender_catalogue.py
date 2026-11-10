"""``check_bitdefender_catalogue.py``: opentide's copy equals the pinned engine's."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_bitdefender_catalogue", ROOT / "scripts" / "build" / "check_bitdefender_catalogue.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _checkout(root: Path, text: str | None) -> dict[str, object]:
    """``cargo metadata`` for a git checkout of language-server at *root*."""
    crate = root / "crates" / "opentide-analysis"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    if text is not None:
        catalogue = root / "catalogs" / "bitdefender" / "criteria.toml"
        catalogue.parent.mkdir(parents=True)
        catalogue.write_text(text, encoding="utf-8")
    return {
        "packages": [
            {"name": "pyo3", "manifest_path": str(root / "pyo3" / "Cargo.toml")},
            {"name": "opentide-analysis", "manifest_path": str(crate / "Cargo.toml")},
        ]
    }


def test_the_engine_catalogue_is_found_at_the_repository_root(tmp_path: Path) -> None:
    script = _script()
    found = script.engine_catalogue(_checkout(tmp_path, "a = 1\n"))
    assert found == tmp_path / "catalogs" / "bitdefender" / "criteria.toml"


def test_an_engine_without_a_catalogue_has_nothing_to_compare(tmp_path: Path) -> None:
    assert _script().engine_catalogue(_checkout(tmp_path, None)) is None


def test_a_different_copy_is_found_and_line_endings_are_not(tmp_path: Path) -> None:
    script = _script()
    vendored = tmp_path / "vendored.toml"
    pinned = tmp_path / "pinned.toml"
    vendored.write_bytes(b"a = 1\n")
    pinned.write_bytes(b"a = 1\r\n")
    assert not script.differs(vendored, pinned)
    pinned.write_bytes(b"a = 2\n")
    assert script.differs(vendored, pinned)


def test_the_bundled_copy_parses_as_the_catalogue() -> None:
    from opentide.platforms.bitdefender.criteria import catalogue, catalogue_path

    assert catalogue_path() == _script().VENDORED.resolve() or catalogue_path().is_file()
    loaded = catalogue()
    assert {"process", "file", "connection", "registry"} == set(loaded.closed_targets)
    assert {"flow", "bitbucket repository"}.isdisjoint(loaded.detection_targets)
    assert loaded.registry_hives["HKEY_LOCAL_MACHINE"] == "HKLM"
