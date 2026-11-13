"""Pytest configuration and shared fixtures.

The suite tests what the Python package still holds (UC-6.2, #841): the
console script, the SDK, the Tide models, the plugin API and the analysis
door, plus the docs' snippets and CI's contracts. The command line itself is
the Rust core's, tested by the goldens and the crates' own tests.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

os.environ.setdefault("TERM_PROGRAM", "vscode")

pytest_plugins = ["tests.corpus_support"]


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


#: Variables that switch on the CLI's CI sinks: annotations on stdout and a job
#: summary file. This suite runs in GitHub Actions, where every CLI test would
#: otherwise print ``::error`` lines into the output it asserts on and append
#: to the real job summary. ``CI`` goes too, so a run there sees the same
#: provider as a local run: none. A test that needs one sets it.
_CI_SINK_ENV = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "GITHUB_STEP_SUMMARY")


@pytest.fixture(autouse=True)
def _isolate_ci_sinks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test outside CI."""
    for name in _CI_SINK_ENV:
        monkeypatch.delenv(name, raising=False)


#: Variables that pick the CLI output mode: a developer running the suite from
#: a coding agent would otherwise get agent mode in every command a test runs,
#: and ``OPENTIDE_DEBUG`` would turn on debug logging.
_OUTPUT_MODE_ENV = (
    "OPENTIDE_OUTPUT",
    "OPENTIDE_DEBUG",
    # The command line's AGENT_VARIABLES (crates/opentide-cli/src/mode.rs).
    "AI_AGENT",
    "CLAUDECODE",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CODEX_CI",
    "COPILOT_AGENT",
    "COPILOT_CLI",
    "OPENCODE",
    "AMP_CURRENT_THREAD_ID",
    "AUGMENT_AGENT",
    "CLINE_ACTIVE",
)


@pytest.fixture(autouse=True)
def _isolate_output_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test outside an agent, with no output mode chosen."""
    for name in _OUTPUT_MODE_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_terminal_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    """No OSC 9;4 in captured output when the suite runs inside Ghostty, kitty, tmux, ...

    Tests of the sequence itself pass their own environment.
    """
    monkeypatch.setenv("OPENTIDE_PROGRESS", "0")


def _restore_environment(saved: dict[str, str]) -> None:
    if dict(os.environ) != saved:
        os.environ.clear()
        os.environ.update(saved)


@pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(fixturedef: Any, request: pytest.FixtureRequest) -> Iterator[Any]:
    """Give every module-, class-, package- or session-scoped fixture its own environment.

    Such a fixture runs before any test's ``_restore_process_environment``
    snapshot, so what it leaves in ``os.environ`` would outlive its scope.
    """
    if fixturedef.scope != "function":
        fixturedef.addfinalizer(partial(_restore_environment, dict(os.environ)))
    return (yield)


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    """Undo ``os.environ`` writes a test makes outside ``monkeypatch``."""
    saved = dict(os.environ)
    yield
    _restore_environment(saved)
