"""The E2E helpers leave the import system as they found it.

``hidden_modules`` runs in the same process as every test after it (one pytest
worker runs unit and E2E tests alike under ``uv run pytest -n 4``), so whatever it
re-imports must not stay reachable once the block ends.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.test_cli.e2e.helpers import hidden_modules

PACKAGE = "hidden_modules_fixture_pkg"
ABSENT = "hidden_modules_fixture_absent"


@pytest.fixture
def package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """``<PACKAGE>.platform.client``, laid out like ``opentide.platforms.sentinel.client``."""
    platform = tmp_path / PACKAGE / "platform"
    platform.mkdir(parents=True)
    (tmp_path / PACKAGE / "__init__.py").write_text("", encoding="utf-8")
    (platform / "__init__.py").write_text("", encoding="utf-8")
    (platform / "client.py").write_text("class Service:\n    pass\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    yield PACKAGE
    for name in [n for n in sys.modules if n == PACKAGE or n.startswith(f"{PACKAGE}.")]:
        del sys.modules[name]


def test_a_purged_package_is_restored_on_its_parent(
    package: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The copy re-imported in the block stayed bound on the parent, without the
    submodules imported before it, so a later ``monkeypatch.setattr`` by dotted path
    raised ``AttributeError`` (``test_tool_deploy_rule_reports_a_refused_rule_as_failed``
    after ``test_validate_query_live_with_a_broken_sdk_advises_a_reinstall``)."""
    client = importlib.import_module(f"{package}.platform.client")
    with hidden_modules(ABSENT, purge=(f"{package}.platform",)):
        importlib.import_module(f"{package}.platform")

    assert sys.modules[package].platform is sys.modules[f"{package}.platform"]
    marker = object()
    monkeypatch.setattr(f"{package}.platform.client.Service", marker)
    assert client.Service is marker


def test_a_package_first_imported_in_the_block_leaves_its_parent(
    package: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module the block imported and then dropped is no longer bound on its parent."""
    importlib.import_module(package)
    with hidden_modules(ABSENT, purge=(f"{package}.platform",)):
        importlib.import_module(f"{package}.platform")

    assert f"{package}.platform" not in sys.modules
    assert not hasattr(sys.modules[package], "platform")
    marker = object()
    monkeypatch.setattr(f"{package}.platform.client.Service", marker)
    assert sys.modules[f"{package}.platform.client"].Service is marker


def test_a_parent_attribute_that_is_not_the_dropped_module_is_left_alone(
    package: str,
) -> None:
    """Only the binding the import made is undone."""
    parent = importlib.import_module(package)
    with hidden_modules(ABSENT, purge=(f"{package}.platform",)):
        importlib.import_module(f"{package}.platform")
        parent.platform = "set by the package itself"

    assert parent.platform == "set by the package itself"
