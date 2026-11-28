"""pydantic is the ``plugins`` extra: the plugin API names it when it is missing (#1180)."""

from __future__ import annotations

import shutil
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, ClassVar

import pytest
from tests.corpus_support import materialise_corpus
from tests.test_platforms.test_plugin_hook import FIXTURE, _env, _run

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


_BARE_PLUGIN = '''\
"""A platform plugin with a configuration model and no import of pydantic."""

from typing import Any, ClassVar

from opentide.plugins import PlatformPlugin


class Bare(PlatformPlugin):
    configuration_model: ClassVar[Any] = object
'''


def test_the_rust_host_carries_the_extra_hint_of_a_plugin_check_that_needs_pydantic(
    tmp_path: Path,
) -> None:
    # The Rust plugin host calls ``check_configuration`` through
    # ``opentide.plugins._invoke``: the ImportError naming the extra reaches
    # ``opentide validate`` as the finding of the block, not as a crash.
    site = tmp_path / "site"
    (site / "bare_acme").mkdir(parents=True)
    (site / "bare_acme" / "__init__.py").write_text(_BARE_PLUGIN, encoding="utf-8")
    # An install without the extra: ``import pydantic`` fails in every child.
    (site / "sitecustomize.py").write_text(
        "import sys\nsys.modules['pydantic'] = None\n", encoding="utf-8"
    )
    info = site / "bare_acme-0.1.0.dist-info"
    info.mkdir()
    info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: bare-acme\nVersion: 0.1.0\n", encoding="utf-8"
    )
    info.joinpath("entry_points.txt").write_text(
        "[opentide.platforms]\nacme = bare_acme:Bare\n", encoding="utf-8"
    )
    repo = materialise_corpus(tmp_path / "workspace")
    shutil.copy(
        FIXTURE / "workspace" / "acme.toml",
        repo / ".opentide" / "configurations" / "platforms" / "acme.toml",
    )
    shutil.copy(
        FIXTURE / "workspace" / "rule-acme-process.yaml",
        repo / "Objects" / "Detection Rules" / "rule-acme-process.yaml",
    )

    _, document = _run(["validate"], _env(site, repo), repo)

    messages = [
        issue["message"]
        for issue in document["report"]["issues"]
        if issue["field_path"] == ["configurations", "acme"]
    ]
    assert messages == [
        "acme: the plugin could not check this block: "
        "ImportError: the plugin API needs pydantic: pip install 'opentide[plugins]'"
    ]
