"""CLI E2E: generate command."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok

from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e


def test_generate_phase_schemas(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli("generate", "schemas")
    assert_json_ok(result)
    schemas = tide_corpus_repo / ".opentide" / "schemas"
    assert (schemas / "rule.1.0.schema.json").is_file()
    assert (schemas / "threat.1.0.schema.json").is_file()


def test_generate_all_on_fresh_setup_repo(invoke_cli, tmp_path: Path) -> None:
    """`opentide generate` must complete on a brand-new setup scaffold (issue #153)."""
    fresh = tmp_path / "fresh-detections"
    run_repo_setup(RepoSetupOptions(path=fresh, name="Fresh", yes=True))
    result = invoke_cli("generate", repo=fresh)
    assert_json_ok(result)
    snippets = fresh / ".vscode" / "model-templates.code-snippets"
    assert snippets.is_file()
    assert (fresh / ".opentide" / "schemas" / "rule.1.0.schema.json").is_file()
    assert (fresh / ".opentide" / "exports" / "objects.export.json").is_file()
