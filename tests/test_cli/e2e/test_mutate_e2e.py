"""CLI E2E: mutate and document commands."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def test_document_command(invoke_cli) -> None:
    result = invoke_cli("document")
    payload = assert_json_ok(result)
    assert "message" in payload


def test_mutate_promote(
    invoke_cli,
    tide_corpus_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging_rule = tide_corpus_repo / "Objects/Detection Rules/rule-0008-staging-promote.yaml"

    def _modified_mdr_files(_plan: object) -> list[Path]:
        return [staging_rule]

    monkeypatch.setattr(
        "opentide.deployment.modified_mdr_files",
        _modified_mdr_files,
    )
    result = invoke_cli(
        "mutate",
        "promote",
        extra_env={"DEPLOYMENT_PLAN": "STAGING"},
    )
    payload = assert_json_ok(result)
    assert payload.get("action") == "promote"
