"""Index manager cache and load behaviour."""

from __future__ import annotations

import pytest

from opentide.core import index_manager as index_mod


def test_index_manager_load_returns_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    index_mod.IndexManager._cache = None
    sample = {"objects": {}, "configurations": {}}
    monkeypatch.setattr(index_mod, "build_registry", lambda: sample)
    index = index_mod.IndexManager.load()
    assert isinstance(index, dict)
    assert "objects" in index


def test_index_manager_reload_clears_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = {"objects": {}, "configurations": {}}
    monkeypatch.setattr(index_mod, "build_registry", lambda: sample)
    index_mod.IndexManager._cache = None
    first = index_mod.IndexManager.load()
    index_mod.IndexManager.reload()
    second = index_mod.IndexManager.load()
    assert first is second
