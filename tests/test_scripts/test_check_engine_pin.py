"""``check_engine_pin.py``: the engine crates come from one source; releases from crates.io."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_engine_pin", ROOT / "scripts" / "build" / "check_engine_pin.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "analysis").mkdir()
    shutil.copy(ROOT / "analysis" / "Cargo.toml", tmp_path / "analysis" / "Cargo.toml")
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_this_repository_agrees() -> None:
    assert _script().problems(ROOT, release=False) == []


def test_a_release_refuses_engine_crates_from_git_or_a_path(repo: Path) -> None:
    script = _script()
    cargo = repo / "analysis" / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    lines = [
        line for line in text.splitlines() if line.startswith(("opentide-analysis", "opentide-lsp"))
    ]
    for line in lines:
        name = line.split(" ", 1)[0]
        text = text.replace(line, f'{name} = {{ path = "../../language-server/crates/{name}" }}')
    cargo.write_text(text, encoding="utf-8")
    assert script.problems(repo, release=False) == []
    refused = script.problems(repo, release=True)
    assert len(refused) == 2 and all("a release builds from crates.io" in item for item in refused)
    for line_name in ("opentide-analysis", "opentide-lsp"):
        text = "\n".join(
            f'{line_name} = "=0.6.0"' if row.startswith(line_name) else row
            for row in text.splitlines()
        )
    cargo.write_text(text + "\n", encoding="utf-8")
    assert script.problems(repo, release=True) == []
    mixed = text.replace('opentide-lsp = "=0.6.0"', 'opentide-lsp = "=0.5.0"')
    cargo.write_text(mixed + "\n", encoding="utf-8")
    assert any("same source and version" in item for item in script.problems(repo, release=True))
