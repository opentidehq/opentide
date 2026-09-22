"""CLI context behaviour."""

from __future__ import annotations

import os
import subprocess
import sys
from contextvars import Token

import pytest

from opentide.cli.context import CliContext, _cli_context, get_context


@pytest.fixture(autouse=True)
def _reset_cli_context() -> None:
    token: Token[CliContext | None] = _cli_context.set(None)
    yield
    _cli_context.reset(token)


def test_cli_context_apply_environment(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTIDE_DATA_ROOT", raising=False)
    ctx = CliContext(repo=tmp_path, debug=True, no_color=True)
    ctx.apply_environment()
    assert os.environ["OPENTIDE_REPO_ROOT"] == str(tmp_path)
    assert os.environ["DEBUG"] == "True"
    assert os.environ["NO_COLOR"] == "1"


def test_no_color_does_not_export_force_color(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rich reads any non-empty FORCE_COLOR, ``"0"`` included, as "force a terminal"."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    CliContext(repo=tmp_path, no_color=True).apply_environment()
    assert os.environ["NO_COLOR"] == "1"
    assert "FORCE_COLOR" not in os.environ


_TYPER_COLOUR_ENV = ("FORCE_COLOR", "NO_COLOR", "GITHUB_ACTIONS", "PY_COLORS")


@pytest.mark.parametrize(
    ("no_color", "env", "colour_system", "force_terminal"),
    [
        pytest.param(True, {"GITHUB_ACTIONS": "true"}, None, False, id="no-color-in-ci"),
        pytest.param(False, {"FORCE_COLOR": "0"}, "auto", False, id="FORCE_COLOR=0"),
        pytest.param(False, {"FORCE_COLOR": "1"}, "auto", True, id="FORCE_COLOR=1"),
        pytest.param(False, {"GITHUB_ACTIONS": "true"}, "auto", True, id="ci-default"),
        pytest.param(
            False,
            {"GITHUB_ACTIONS": "true", "FORCE_COLOR": "0"},
            "auto",
            False,
            id="ci-FORCE_COLOR=0",
        ),
        pytest.param(False, {}, "auto", None, id="detect"),
        pytest.param(False, {"PY_COLORS": "1"}, "auto", True, id="PY_COLORS=1"),
        pytest.param(False, {"PY_COLORS": "0"}, "auto", False, id="PY_COLORS=0"),
        pytest.param(
            False,
            {"GITHUB_ACTIONS": "true", "PY_COLORS": "0"},
            "auto",
            False,
            id="ci-PY_COLORS=0",
        ),
        pytest.param(
            False, {"FORCE_COLOR": "1", "PY_COLORS": "0"}, "auto", True, id="FORCE_COLOR-wins"
        ),
    ],
)
def test_sync_typer_rendering(
    monkeypatch: pytest.MonkeyPatch,
    no_color: bool,
    env: dict[str, str],
    colour_system: str | None,
    force_terminal: bool | None,
) -> None:
    """Typer's import-time ``FORCE_TERMINAL`` treats ``FORCE_COLOR=0`` as "force"."""
    from typer import rich_utils

    from opentide.cli.context import sync_typer_rendering

    for name in _TYPER_COLOUR_ENV:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    sync_typer_rendering(no_color=no_color)
    rendering = (rich_utils.COLOR_SYSTEM, rich_utils.FORCE_TERMINAL)
    assert rendering == (colour_system, force_terminal)


def test_importing_the_cli_leaves_a_host_apps_typer_rendering_alone() -> None:
    """``opentide.ci.*`` imports ``opentide.cli``; a library import must not restyle a host app.

    A fresh interpreter, because this process imported ``opentide.cli`` long ago.
    """
    script = (
        "from typer import rich_utils\n"
        "rich_utils.COLOR_SYSTEM = None\n"
        "rich_utils.FORCE_TERMINAL = False\n"
        "import opentide.ci.gitlab\n"
        "import opentide.cli\n"
        "print(rich_utils.COLOR_SYSTEM, rich_utils.FORCE_TERMINAL)\n"
    )
    env = {k: v for k, v in os.environ.items() if k not in _TYPER_COLOUR_ENV}
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env | {"GITHUB_ACTIONS": "true"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.split() == ["None", "False"]


def test_apply_environment_keeps_an_inherited_workspace(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ``--repo`` the exported workspace stays authoritative."""
    other = tmp_path / "other"
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(other))
    CliContext(repo=tmp_path).apply_environment()
    assert os.environ["OPENTIDE_TIDE_WORKSPACE"] == str(other)


def test_explicit_repo_overrides_an_exported_workspace(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#249: a stale ``OPENTIDE_TIDE_WORKSPACE`` silently beat ``--repo``.

    ``discover_workspace`` reads that variable before it consults the repo root,
    so ``opentide --repo X validate`` validated Y and reported success.
    """
    other = tmp_path / "other"
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(other))
    CliContext(repo=tmp_path, repo_explicit=True).apply_environment()
    assert os.environ["OPENTIDE_TIDE_WORKSPACE"] == str(tmp_path)


def test_cli_context_set_deployment_plan() -> None:
    ctx = CliContext()
    ctx.set_deployment_plan("staging")
    assert os.environ["DEPLOYMENT_PLAN"] == "STAGING"


def test_get_context_from_contextvar() -> None:
    cli = CliContext(json_output=True)
    cli.activate()
    assert get_context() is cli


def test_get_context_raises_when_uninitialised() -> None:
    with pytest.raises(TypeError, match="CLI context not initialised"):
        get_context(None)
