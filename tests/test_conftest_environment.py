"""The root conftest keeps ``os.environ`` writes inside the scope that made them."""

from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]

_CONFTEST = """
from tests.conftest import _restore_process_environment, pytest_fixture_setup  # noqa: F401
"""

_LEAKS = """
import os

import pytest


@pytest.fixture(scope="module")
def workspace():
    # What an in-process CLI call does: CliRunner(env=...) does not undo it.
    os.environ["OPENTIDE_LEAK_CHECK"] = "from a module fixture"
    return "ws"


def test_uses_the_fixture(workspace):
    assert os.environ["OPENTIDE_LEAK_CHECK"] == "from a module fixture"


def test_the_fixture_holds_for_its_module(workspace):
    assert os.environ["OPENTIDE_LEAK_CHECK"] == "from a module fixture"


def test_a_test_write_is_undone_after_it():
    os.environ["OPENTIDE_TEST_WRITE"] = "1"
"""

_LATER = """
import os


def test_nothing_leaks_into_the_next_module():
    assert "OPENTIDE_LEAK_CHECK" not in os.environ
    assert "OPENTIDE_TEST_WRITE" not in os.environ
"""


def test_a_module_fixture_cannot_leak_environment_into_later_modules(
    pytester: pytest.Pytester,
) -> None:
    pytester.makeconftest(_CONFTEST)
    pytester.makepyfile(test_a_leaks=_LEAKS, test_b_later=_LATER)
    result = pytester.runpytest_inprocess("-p", "no:randomly", "-p", "no:cacheprovider")
    result.assert_outcomes(passed=4)


_CACHES_ROOTS = """
from opentide.core.root import get_data_root, get_repo_root


def test_an_override_fills_the_root_caches(monkeypatch, tmp_path):
    # What an in-process CLI call does: CliRunner(env=...) takes the variables
    # back, but the roots resolved from them stay cached.
    get_repo_root.cache_clear()
    get_data_root.cache_clear()
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path / "leaked-repo"))
    monkeypatch.setenv("OPENTIDE_DATA_ROOT", str(tmp_path / "leaked-data"))
    assert get_repo_root() == tmp_path / "leaked-repo"
    assert get_data_root() == tmp_path / "leaked-data"
"""

_READS_ROOTS = """
from opentide.core.root import get_data_root, get_repo_root


def test_the_next_test_resolves_its_own_roots():
    assert get_repo_root().name != "leaked-repo"
    assert get_data_root().name != "leaked-data"
"""


def test_a_cached_root_does_not_outlive_the_environment_it_came_from(
    pytester: pytest.Pytester,
) -> None:
    pytester.makeconftest(_CONFTEST)
    pytester.makepyfile(test_a_caches=_CACHES_ROOTS, test_b_reads=_READS_ROOTS)
    result = pytester.runpytest_inprocess("-p", "no:randomly", "-p", "no:cacheprovider")
    result.assert_outcomes(passed=2)
