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
