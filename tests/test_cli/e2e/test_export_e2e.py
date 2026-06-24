"""CLI E2E: export commands."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def test_export_navigator_creates_artifact(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli("export", "navigator")
    assert_json_ok(result)
    export_path = tide_corpus_repo / ".opentide" / "exports" / "attack-navigator.json"
    assert export_path.is_file()
