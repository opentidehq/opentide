"""CLI context behaviour."""

from __future__ import annotations

import os
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
