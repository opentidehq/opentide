"""``check_bitdefender_catalogue.py``: opentide's copy equals the pinned engine's.

The engine's ``opentide-tide`` reads its catalogs from the workspace root in a
git checkout and from ``assets/catalogs`` in a published crate: both are found.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_bitdefender_catalogue", ROOT / "scripts" / "build" / "check_bitdefender_catalogue.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # A dataclass looks its module up in sys.modules while it is defined.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _metadata(crate: Path) -> dict[str, object]:
    return {
        "packages": [
            {"name": "pyo3", "manifest_path": str(crate.parent / "pyo3" / "Cargo.toml")},
            {"name": "opentide-tide", "manifest_path": str(crate / "Cargo.toml")},
        ]
    }


def _crate(root: Path, *, supports: bool) -> Path:
    crate = root / "crates" / "opentide-tide"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    if supports:
        (crate / "src" / "bitdefender.rs").write_text("", encoding="utf-8")
    return crate


def _catalogue(catalogs: Path, text: str) -> None:
    path = catalogs / "bitdefender" / "criteria.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_a_git_checkout_reads_the_workspace_catalogs(tmp_path: Path) -> None:
    crate = _crate(tmp_path, supports=True)
    _catalogue(tmp_path / "catalogs", "a = 1\n")
    # A vendored copy left in the crate never shadows the checkout's.
    _catalogue(crate / "assets" / "catalogs", "stale = 1\n")
    found = _script().engine_catalogue(_metadata(crate))
    assert found.path == tmp_path / "catalogs" / "bitdefender" / "criteria.toml"
    assert found.supports_bitdefender


def test_a_published_crate_reads_its_assets(tmp_path: Path) -> None:
    crate = tmp_path / "registry" / "opentide-tide-0.13.0"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    _catalogue(crate / "assets" / "catalogs", "a = 1\n")
    found = _script().engine_catalogue(_metadata(crate))
    assert found.path == crate / "assets" / "catalogs" / "bitdefender" / "criteria.toml"
    assert found.supports_bitdefender


def test_an_engine_before_bitdefender_support_has_nothing_to_compare(tmp_path: Path) -> None:
    crate = _crate(tmp_path, supports=False)
    (tmp_path / "catalogs" / "tide").mkdir(parents=True)
    found = _script().engine_catalogue(_metadata(crate))
    assert not found.supports_bitdefender
    assert not found.path.is_file()


def test_no_tide_crate_is_not_found() -> None:
    assert _script().engine_catalogue({"packages": []}) is None


def test_a_different_copy_is_found_and_line_endings_are_not(tmp_path: Path) -> None:
    script = _script()
    vendored = tmp_path / "vendored.toml"
    pinned = tmp_path / "pinned.toml"
    vendored.write_bytes(b"a = 1\n")
    pinned.write_bytes(b"a = 1\r\n")
    assert not script.differs(vendored, pinned)
    pinned.write_bytes(b"a = 2\n")
    assert script.differs(vendored, pinned)


def _run_main(
    monkeypatch: pytest.MonkeyPatch, script: ModuleType, metadata: dict[str, object]
) -> int:
    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(metadata), stderr="")

    monkeypatch.setattr(script.subprocess, "run", fake_run)
    return int(script.main())


@pytest.mark.parametrize(
    ("supports", "engine_text", "expected"),
    [
        (False, None, 0),  # the transition: an engine that predates Bitdefender
        (True, None, 1),  # supports Bitdefender, carries no catalogue
        (True, "different = 1\n", 1),
        (True, "same", 0),
    ],
)
def test_main(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    supports: bool,
    engine_text: str | None,
    expected: int,
) -> None:
    script = _script()
    vendored = tmp_path / "vendored.toml"
    vendored.write_text("same", encoding="utf-8")
    monkeypatch.setattr(script, "VENDORED", vendored)
    monkeypatch.setattr(script, "ROOT", tmp_path)
    crate = _crate(tmp_path / "engine", supports=supports)
    (tmp_path / "engine" / "catalogs").mkdir()
    if engine_text is not None:
        _catalogue(tmp_path / "engine" / "catalogs", engine_text)
    assert _run_main(monkeypatch, script, _metadata(crate)) == expected


def test_the_bundled_copy_parses_as_the_catalogue() -> None:
    from opentide.platforms.bitdefender.criteria import catalogue, catalogue_path

    assert catalogue_path().read_bytes() == _script().VENDORED.read_bytes()
    loaded = catalogue()
    assert {"process", "file", "connection", "registry"} == set(loaded.closed_targets)
    assert {"flow", "bitbucket repository"}.isdisjoint(loaded.detection_targets)
    assert loaded.registry_hives["HKEY_LOCAL_MACHINE"] == "HKLM"
