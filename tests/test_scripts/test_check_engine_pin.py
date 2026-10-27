"""``scripts/build/check_engine_pin.py``: opentide and its engine agree; releases use crates.io."""

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
    shutil.copy(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    for name in ("pyproject.toml", "Cargo.toml"):
        shutil.copy(ROOT / "analysis" / name, tmp_path / "analysis" / name)
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_this_repository_agrees() -> None:
    assert _script().problems(ROOT, release=False) == []


def test_a_pin_that_drifts_from_the_engine_version_is_reported(repo: Path) -> None:
    script = _script()
    version = (repo / "analysis" / "pyproject.toml").read_text(encoding="utf-8")
    current = next(line for line in version.splitlines() if line.startswith("version = "))
    _edit(repo / "analysis" / "pyproject.toml", current, 'version = "9.9.9"')
    found = script.problems(repo, release=False)
    assert any("must pin opentide-analysis==9.9.9" in item for item in found)
    assert any("analysis/Cargo.toml says" in item for item in found)


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


def _published_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_engine_published", ROOT / "scripts" / "build" / "check_engine_published.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sdist(files: dict[str, bytes]) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"opentide_analysis-0.6.0/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_a_published_engine_with_the_same_sources_needs_no_bump() -> None:
    script = _published_script()
    local = script.local_sources(ROOT)
    cargo = local["Cargo.toml"].replace(b"[lib]", b'readme = "README.md"\n\n[lib]', 1)
    published = script.sdist_sources(_sdist({**local, "Cargo.toml": cargo, "PKG-INFO": b"x"}))
    assert script.differences(local, published) == [], "maturin's readme line is not a change"


def test_a_changed_engine_under_a_published_version_is_refused() -> None:
    script = _published_script()
    local = script.local_sources(ROOT)
    old_rev = local["Cargo.toml"].replace(b'rev = "', b'rev = "0', 2)
    published = script.sdist_sources(_sdist({**local, "Cargo.toml": old_rev}))
    assert script.differences(local, published) == ["Cargo.toml"]
    without_binding = script.sdist_sources(_sdist({**local, "src/lib.rs": b"// older"}))
    assert script.differences(local, without_binding) == ["src/lib.rs"]
