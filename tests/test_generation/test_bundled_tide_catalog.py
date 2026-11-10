"""The engine's bundled Tide catalog is what this checkout's models generate (#800).

The engine crates compile in the Tide catalog under ``data/catalogs/tide/generated/``
(``fields.json``, ``deprecations.json``), beside the router in
``data/catalogs/tide/schemas/`` and the key lists of
``highlights/queries/tide/highlights.scm``. ``scripts/engine/sync_opentide_schemas.py``
generates all of them from ``src/opentide``; each revision's reference schema beside the
router is generated from the Rust models and checked by ``cargo xtask codegen`` (UC-1.8b,
#900). Until the engine generates them itself
(UC-1.8), a change to the models, a vocabulary or a pin regenerates them in the same
change, or these tests fail: they replace the cross-repository gate
(``scripts/build/check_engine_catalog.py``) and language-server's opentide canary.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATED = ROOT / "data" / "catalogs" / "tide" / "generated"
FIX = "uv run python scripts/engine/sync_opentide_schemas.py"


@pytest.fixture
def empty_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Generate as the script does from the repository root: with no workspace
    configuration (log sources, statuses), and none of an earlier test's state."""
    from tests.corpus_support import clear_runtime_caches

    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"):
        monkeypatch.setenv(name, str(tmp_path))
    clear_runtime_caches()
    yield tmp_path
    clear_runtime_caches()


def _script() -> ModuleType:
    path = ROOT / "scripts" / "engine" / "sync_opentide_schemas.py"
    spec = importlib.util.spec_from_file_location("sync_opentide_schemas", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.usefixtures("empty_workspace")
def test_the_committed_catalogs_are_what_the_models_generate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _script()
    assert script.check(script.expected_outputs()) == 0, (
        f"{capsys.readouterr().err}\nregenerate them in this change: {FIX}"
    )


@pytest.mark.usefixtures("empty_workspace")
def test_a_stale_catalog_names_the_field_and_the_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = tmp_path / "generated"
    shutil.copytree(GENERATED, stale)
    fields = json.loads((stale / "fields.json").read_text(encoding="utf-8"))
    fields["fields"] = [
        row
        for row in fields["fields"]
        if (row["schema"], row["path"]) != ("rule::1.1", "metadata.reviewed")
    ]
    (stale / "fields.json").write_text(json.dumps(fields), encoding="utf-8")
    script = _script()
    monkeypatch.setattr(script, "GENERATED", stale)
    assert script.check(script.expected_outputs()) == 1
    err = capsys.readouterr().err
    assert "fields.json: 1 new (rule::1.1 metadata.reviewed)" in err
    assert FIX in err


def test_the_engine_compiles_in_the_committed_catalog() -> None:
    """The engine opentide built is the one these files describe: an engine built
    before the catalog changed (``uv sync`` not rebuilding it) fails here."""
    from opentide.analysis import engine

    fields, deprecations = engine().bundled_catalog()
    assert fields == (GENERATED / "fields.json").read_text(encoding="utf-8")
    assert deprecations == (GENERATED / "deprecations.json").read_text(encoding="utf-8")


def test_the_script_reads_this_checkouts_models() -> None:
    import opentide

    script = _script()
    assert script.PACKAGE == ROOT / "src" / "opentide"
    assert Path(opentide.__file__).resolve().parent == script.PACKAGE
