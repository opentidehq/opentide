"""CLI E2E: ``deploy --persist-state-externally`` applies to its own run only (#554)."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.test_cli.e2e.helpers import EVERY_RULE, uncomment_tenants

from opentide.deployment.external_ids import PERSIST_EXTERNALLY_ENV

pytestmark = pytest.mark.cli_e2e


@pytest.fixture
def seen(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> list[str | None]:
    """The flag's environment value each deployer call saw."""
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")
    observed: list[str | None] = []
    deployer = MagicMock()
    deployer.deploy.side_effect = lambda **_: observed.append(
        os.environ.get(PERSIST_EXTERNALLY_ENV)
    )

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"sentinel": deployer} if "sentinel" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    return observed


def _deploy(invoke_cli, *extra: str):
    return invoke_cli("deploy", "--platform", "sentinel", *EVERY_RULE, "--skip-promotion", *extra)


def test_the_flag_reaches_the_deployers(invoke_cli, seen: list[str | None]) -> None:
    result = _deploy(invoke_cli, "--persist-state-externally")
    assert result.exit_code == 0, result.stdout + result.stderr
    assert seen == ["1"]


def test_without_the_flag_an_inherited_value_is_cleared(
    invoke_cli, seen: list[str | None], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An earlier run in the same process (MCP, tests) must not lift the refusal."""
    monkeypatch.setenv(PERSIST_EXTERNALLY_ENV, "1")
    result = _deploy(invoke_cli)
    assert result.exit_code == 0, result.stdout + result.stderr
    assert seen == [None]
