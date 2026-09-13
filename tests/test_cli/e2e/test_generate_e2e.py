"""CLI E2E: generate command."""

from __future__ import annotations

import json
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


def test_generate_all_on_corpus_enriches_vocab_actors(invoke_cli, tide_corpus_repo: Path) -> None:
    """Full generate on populated objects must enrich object ``actors[].name``."""
    result = invoke_cli("generate")
    assert_json_ok(result)
    export_path = tide_corpus_repo / ".opentide" / "exports" / "objects.export.json"
    assert export_path.is_file()
    catalog = json.loads(export_path.read_text(encoding="utf-8"))
    threat_row = next(
        row for row in catalog if row["uuid"] == "00000000-0000-4000-8001-000000000001"
    )
    assert "APT1" in threat_row["actors"] or "G0006" in threat_row["actors"]
    assert "T1059" in threat_row["attack"]
