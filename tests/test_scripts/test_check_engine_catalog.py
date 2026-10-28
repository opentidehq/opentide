"""``check_engine_catalog.py``: the pinned engine carries the catalog the models generate (#679)."""

from __future__ import annotations

import importlib.util
import json
import os
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from opentide import analysis
from opentide.analysis import EngineUnavailableError

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _fresh_registry() -> Iterator[None]:
    """The script runs in a process of its own; here, earlier tests' registry
    state (another workspace) must not reach the empty one it generates in."""
    from tests.corpus_support import clear_runtime_caches

    clear_runtime_caches()
    yield
    clear_runtime_caches()


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_engine_catalog", ROOT / "scripts" / "build" / "check_engine_catalog.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_pinned_engine_is_current(capsys: pytest.CaptureFixture[str]) -> None:
    before = {
        name: os.environ.get(name) for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE")
    }
    assert _script().main() == 0
    assert "bundled catalogs (opentide-analysis" in capsys.readouterr().out
    # The empty workspace it generates in is gone again.
    assert {name: os.environ.get(name) for name in before} == before


def test_a_stale_engine_names_the_fields_and_the_fix(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fields, deprecations = analysis.engine().bundled_catalog()
    assert fields is not None
    stale = json.loads(fields)
    stale["fields"] = [row for row in stale["fields"] if row["path"] != "metadata.reviewed"]
    engine = SimpleNamespace(bundled_catalog=lambda: (json.dumps(stale), deprecations))
    monkeypatch.setattr(analysis, "engine", lambda: engine)
    monkeypatch.setattr(analysis, "engine_versions", lambda: {"package": "0.0.0", "engine": "0"})
    assert _script().main() == 1
    err = capsys.readouterr().err
    assert "bundled fields.json is stale: 1 new (rule::1.1 metadata.reviewed)" in err
    assert "scripts/sync_opentide_schemas.py" in err
    assert "analysis/Cargo.toml" in err


def test_without_the_engine_it_fails_with_the_reinstall_step(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing() -> None:
        raise EngineUnavailableError("No module named 'opentide_analysis._native'")

    monkeypatch.setattr(analysis, "engine", missing)
    assert _script().main() == 1
    assert "help: reinstall opentide" in capsys.readouterr().err
