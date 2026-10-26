"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

os.environ.setdefault("TERM_PROGRAM", "vscode")

pytest_plugins = ["tests.corpus_support"]

_repo_patcher: patch | None = None
_original_find_workspace_root = None


def _test_find_workspace_root(start: Path | None = None) -> Path:
    """Pin default repo root for imports; honour env override and explicit *start*.

    In-process tests therefore never discover a root from the cwd; cover
    discovery with an explicit *start* or through a console-script subprocess.
    """
    if start is not None:
        assert _original_find_workspace_root is not None
        return _original_find_workspace_root(start)
    override = os.environ.get("OPENTIDE_REPO_ROOT")
    if override:
        return Path(override)
    return ROOT


def pytest_configure(config: object) -> None:
    """Pin repo root before Engines modules resolve paths at import time."""
    global _repo_patcher, _original_find_workspace_root
    import opentide.core.root as root_mod

    _original_find_workspace_root = root_mod.find_workspace_root
    _repo_patcher = patch.object(root_mod, "find_workspace_root", _test_find_workspace_root)
    _repo_patcher.start()


def pytest_unconfigure(config: object) -> None:
    global _repo_patcher
    if _repo_patcher is not None:
        _repo_patcher.stop()
        _repo_patcher = None


# `git` resolves these BEFORE the `cwd` a caller passes, so a test that shells
# out to git while one of them is set operates on the repository THEY name --
# not on its own fixture.
#
# That is not hypothetical. `git push` exports `GIT_DIR` to its hooks, and this
# project registers `ci-local-full` as a pre-push hook that runs this suite. A
# contributor pushing therefore ran the git fixtures against their own
# checkout: it was switched to a fixture branch, a commit deleting 890 files
# was created, and that commit was published.
#
# Stripping them here rather than in each helper is deliberate --
# `subprocess` inherits `os.environ`, so one autouse fixture covers every test
# that shells out to git, including ones added later. Author and committer
# identity are intentionally NOT stripped: tests set those on purpose, and they
# cannot redirect git at a different repository.
_GIT_LOCATION_ENV = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_WORK_TREE",
)


@pytest.fixture(autouse=True)
def _isolate_git_location_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the repository-location ``GIT_*`` family for every test.

    Applies to all tests, not only the git ones: any test that shells out to a
    tool which itself invokes git inherits the same hazard.
    """
    for name in _GIT_LOCATION_ENV:
        monkeypatch.delenv(name, raising=False)


#: The variables that make a CI run a pull or merge request run. A GitHub
#: Actions job for a pull request exports ``GITHUB_EVENT_NAME=pull_request``,
#: so a test that sets ``GITHUB_ACTIONS`` or ``CI`` to simulate a push would
#: otherwise run as a pull request there and nowhere else.
_CHANGE_REQUEST_ENV = ("GITHUB_EVENT_NAME", "CI_PIPELINE_SOURCE", "BUILD_REASON")


@pytest.fixture(autouse=True)
def _isolate_ci_event_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test as a push run; a test that needs a pull request sets the event."""
    for name in _CHANGE_REQUEST_ENV:
        monkeypatch.delenv(name, raising=False)


#: Variables that pick the CLI output mode. A developer running the suite from a
#: coding agent (``CLAUDECODE``, ``AI_AGENT``, ...) would otherwise get agent
#: mode in every CLI test, and ``OPENTIDE_DEBUG`` would turn on debug logging.
_OUTPUT_MODE_ENV = ("OPENTIDE_OUTPUT", "OPENTIDE_DEBUG")


@pytest.fixture(autouse=True)
def _isolate_output_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Start every test outside an agent, with no output mode chosen yet."""
    from opentide.cli.ui.mode import AGENT_VARIABLES, reset_mode

    for name in (*AGENT_VARIABLES, *_OUTPUT_MODE_ENV):
        monkeypatch.delenv(name, raising=False)
    reset_mode()
    yield
    reset_mode()


@pytest.fixture
def metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


@pytest.fixture
def rule_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Test rule",
        "metadata": metadata,
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": ["T1059"],
        "platforms": {},
    }


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    """Undo ``os.environ`` writes a test makes outside ``monkeypatch``.

    In-process CLI calls push ``--repo`` / ``--no-color`` into the
    environment for engine modules and never take them back; without this every
    later test in the worker inherits them and output checks depend on order.
    """
    saved = dict(os.environ)
    yield
    if dict(os.environ) != saved:
        os.environ.clear()
        os.environ.update(saved)


@pytest.fixture(autouse=True)
def _restore_typer_rendering() -> Iterator[None]:
    """``--no-color`` switches Typer's module-level styling off for the process."""
    from typer import rich_utils

    saved = (rich_utils.COLOR_SYSTEM, rich_utils.FORCE_TERMINAL)
    yield
    rich_utils.COLOR_SYSTEM, rich_utils.FORCE_TERMINAL = saved


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """In-process CLI calls re-initialise logging for the whole process.

    After a ``--json`` invocation every later test saw ``is_json_output()`` true,
    so human-output assertions passed or failed by test order, and root handlers
    kept writing to the finished ``CliRunner`` stream. pytest's own capture
    handlers are swapped per phase and left alone.
    """
    import logging

    from opentide.core.logging import config

    def installed(root: logging.Logger) -> list[logging.Handler]:
        return [h for h in root.handlers if type(h).__module__ != "_pytest.logging"]

    root = logging.getLogger()
    saved_state = (config._config, config._console, config._stdout_console)
    saved_handlers, saved_level = installed(root), root.level
    yield
    config._config, config._console, config._stdout_console = saved_state
    for handler in installed(root):
        if handler not in saved_handlers:
            root.removeHandler(handler)
    for handler in saved_handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(saved_level)


@pytest.fixture(autouse=True)
def _reset_opentide_registry() -> None:
    """Prevent tests from polluting singleton state."""
    yield
    from tests.registry_support import reset_opentide_singletons

    reset_opentide_singletons()


@pytest.fixture
def tide_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect tide instance outputs into a repo-local workspace for portable CI."""
    from opentide.generation.artifact_gate import TIDE_WORKSPACE_DIR
    from opentide.registry.discovery import OPENTIDE_DIR

    workspace = ROOT / TIDE_WORKSPACE_DIR
    workspace.mkdir(parents=True, exist_ok=True)
    for rel in (
        f"{OPENTIDE_DIR}/schemas",
        f"{OPENTIDE_DIR}/templates",
        f"{OPENTIDE_DIR}/exports",
        f"{OPENTIDE_DIR}/inflight",
        f"{OPENTIDE_DIR}/configurations",
        "objects/threats",
        "objects/objectives",
        "objects/rules",
        ".vscode",
    ):
        (workspace / rel).mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(workspace.resolve()))
    return workspace
