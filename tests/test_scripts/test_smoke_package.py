"""``scripts/build/smoke_package.py``: the release's smoke of an installed opentide."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The script reads pyproject.toml with tomllib (Python 3.11 or later): the
# release runs it on 3.12.
pytest.importorskip("tomllib")


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "smoke_package", ROOT / "scripts" / "build" / "smoke_package.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_corpus_is_copied_into_the_current_layout(tmp_path: Path) -> None:
    script = _script()
    workspace = script.materialise(tmp_path / "corpus")
    for folder in ("objects/threats", "objects/objectives", "objects/rules"):
        assert (workspace / folder).is_dir(), folder
        assert not (workspace / folder).is_symlink(), folder
        assert any((workspace / folder).iterdir()), folder
    assert any((workspace / ".opentide" / "configurations").iterdir())
    for folder in ("schemas", "templates", "exports", "inflight"):
        assert (workspace / ".opentide" / folder).is_dir(), folder


def test_the_requirements_are_pyprojects(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _script()
    monkeypatch.setattr(script.importlib.metadata, "requires", lambda _name: ["pydantic >=2.0"])
    assert script.check_requirements() == ["pydantic>=2.0"]


@pytest.mark.parametrize(
    "requires",
    [
        ["pydantic>=2.0", "typer>=0.27"],  # a dependency the wheel gained
        [],  # or lost
        ["pydantic>=1.0"],
    ],
)
def test_another_requirement_fails(monkeypatch: pytest.MonkeyPatch, requires: list[str]) -> None:
    script = _script()
    monkeypatch.setattr(script.importlib.metadata, "requires", lambda _name: requires)
    with pytest.raises(SystemExit, match=r"but pyproject\.toml declares"):
        script.check_requirements()


def test_it_needs_the_version() -> None:
    with pytest.raises(SystemExit):
        _script().main([])
