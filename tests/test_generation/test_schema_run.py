"""Tests for schema generation entrypoint."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opentide.generation.lsp_catalog import CATALOG_DIR

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway detection workspace, so `run()` writes nothing in the repository.

    Without it `run()` resolved the workspace from the process: the tracked
    `tests/fixtures/generation/tide_workspace`, or the repository root on a
    checkout without it, and rewrote their visibility schema with the mock below.
    """
    (tmp_path / ".opentide").mkdir()
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    return tmp_path


def _run_with_mocked_exports(workspace: Path) -> tuple[MagicMock, MagicMock]:
    """`schema.run()` with the heavy exports mocked; *workspace* is where it writes."""
    assert (workspace / ".opentide").is_dir()
    from opentide.generation import schema

    with (
        patch("opentide.generation.schema.export_all_registered_schemas") as mock_export,
        patch(
            "opentide.generation.schema.generate_configuration_schema",
            return_value={"type": "object"},
        ),
        patch("opentide.generation.schema.export_opentide_router") as mock_router,
    ):
        schema.run()
    return mock_export, mock_router


def test_schema_run_invokes_pipeline(workspace: Path) -> None:
    mock_export, mock_router = _run_with_mocked_exports(workspace)
    mock_export.assert_called_once()
    mock_router.assert_called_once()
    assert (workspace / ".opentide/schemas/visibility.1.0.schema.json").is_file()
    assert sorted(p.name for p in (workspace / CATALOG_DIR).iterdir()) == [
        "deprecations.json",
        "fields.json",
    ]


def test_schema_run_after_a_test_left_a_partial_configuration_bound(workspace: Path) -> None:
    """The flake: an earlier test on the worker bound a partial configuration index.

    `schema_pipeline` keeps `Opentide.Configurations.Index` in a module global
    behind `_runtime_ready`. The autouse registry reset must clear that binding
    too, or the LSP catalog step fails with `KeyError: 'systems'`.
    """
    from tests.registry_support import reset_opentide_singletons

    from opentide.generation import schema_pipeline

    schema_pipeline._ensure_runtime_context()
    schema_pipeline.CONFIG_INDEX = {}  # what a test with a partial index leaves behind
    reset_opentide_singletons()  # what the autouse fixture runs between the two tests

    _run_with_mocked_exports(workspace)
    assert (workspace / CATALOG_DIR / "fields.json").is_file()


def _snapshot(folder: Path) -> dict[str, tuple[int, int, bytes]]:
    """Every file under *folder*, by relative path; empty when it does not exist.

    Inode and mtime as well as bytes: a checkout where an earlier run already wrote the same
    bytes there would otherwise not see a rewrite (writes replace the file atomically).
    """
    if not folder.is_dir():
        return {}
    snapshot: dict[str, tuple[int, int, bytes]] = {}
    for path in folder.rglob("*"):
        if path.is_file():
            stat = path.stat()
            snapshot[path.relative_to(folder).as_posix()] = (
                stat.st_ino,
                stat.st_mtime_ns,
                path.read_bytes(),
            )
    return snapshot


def test_schema_run_writes_nothing_in_the_repository(workspace: Path) -> None:
    watched = [ROOT / ".opentide", ROOT / "tests/fixtures/generation/tide_workspace/.opentide"]
    before = [_snapshot(folder) for folder in watched]
    _run_with_mocked_exports(workspace)
    assert [_snapshot(folder) for folder in watched] == before
