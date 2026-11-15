"""pydantic is the ``plugins`` extra: the plugin API names it when it is missing (#1180)."""

from __future__ import annotations

import sys
from importlib import metadata
from typing import Any, ClassVar

import pytest

from opentide import plugins


class _Configured(plugins.PlatformPlugin):
    configuration_model: ClassVar[Any] = object


def _without_pydantic(monkeypatch: pytest.MonkeyPatch) -> None:
    """``import pydantic`` fails as it does in an install without the extra."""
    monkeypatch.setitem(sys.modules, "pydantic", None)


def test_check_configuration_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    _without_pydantic(monkeypatch)
    with pytest.raises(ImportError, match=r"pip install 'opentide\[plugins\]'") as raised:
        _Configured().check_configuration({})
    assert raised.value.name == "pydantic"


def test_a_plugin_without_a_model_needs_no_pydantic(monkeypatch: pytest.MonkeyPatch) -> None:
    _without_pydantic(monkeypatch)
    assert plugins.PlatformPlugin().check_configuration({}) == []


class _Point:
    """An entry point of a plugin whose module imports pydantic, as most do."""

    def __init__(self, name: str, error: Exception) -> None:
        self.name = name
        self._error = error

    def load(self) -> object:
        raise self._error


def test_a_plugin_that_cannot_import_pydantic_is_reported_with_the_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = ModuleNotFoundError("No module named 'pydantic'", name="pydantic")
    other = ModuleNotFoundError("No module named 'acme_sdk'", name="acme_sdk")
    points = [_Point("acme", missing), _Point("other", other)]
    monkeypatch.setattr(metadata, "entry_points", lambda group: points)

    found = {item["id"]: item["error"] for item in plugins._discover()}

    assert "pip install 'opentide[plugins]'" in found["acme"]
    assert found["acme"].startswith("ModuleNotFoundError: No module named 'pydantic'")
    assert found["other"] == "ModuleNotFoundError: No module named 'acme_sdk'"
