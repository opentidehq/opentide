"""CLI E2E for the two documented commands nothing ever ran unmocked (#266).

`generate extract` and `generate explorer` were only ever exercised with
`run_extract` patched out or as a CI-template string assertion, which is why
#242 (misleading module-not-found, `KeyError` at import) and #202 (unregistered
command, wrong `run` import) stayed green.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import sdk_installed

from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e


def _fresh_repo(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    run_repo_setup(RepoSetupOptions(path=repo, name=name, yes=True))
    return repo


def test_extract_modules_import_without_side_effects() -> None:
    """Issue #242: importing an importer must not build a tenant or call an API."""
    module = importlib.import_module("opentide.extraction.mde_importer")
    assert callable(module.run)


@pytest.mark.parametrize("target", ["sentinel", "defender"])
def test_generate_extract_emits_one_json_document(invoke_cli, tmp_path: Path, target: str) -> None:
    """Whatever goes wrong, --json owes the caller exactly one result object."""
    repo = _fresh_repo(tmp_path, f"extract-{target}")
    result = invoke_cli("generate", "extract", target, repo=repo)
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["ok"] is False
    assert payload["status"] == "failed"
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined
    assert "KeyError" not in combined


def test_generate_extract_sentinel_names_the_missing_extra(invoke_cli, tmp_path: Path) -> None:
    """A missing vendor SDK is not a missing module (#242)."""
    if sdk_installed("azure.monitor.query"):  # pragma: no cover
        pytest.skip("azure SDK installed; the missing-extra path cannot be observed here")
    repo = _fresh_repo(tmp_path, "extract-extra")
    result = invoke_cli("generate", "extract", "sentinel", repo=repo)
    message = parse_cli_json(result)["error"]
    assert "opentide[sentinel]" in message
    assert "Extraction module not found" not in message


def test_generate_extract_defender_reports_unconfigured_tenants(invoke_cli, tmp_path: Path) -> None:
    """The old dummy tenant raised `KeyError: ''` before the CLI could speak."""
    repo = _fresh_repo(tmp_path, "extract-defender-tenants")
    result = invoke_cli("generate", "extract", "defender", repo=repo)
    assert "tenants" in parse_cli_json(result)["error"]


def test_generate_explorer_is_registered_and_writes_the_bundle(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    """Issue #202: the phase imported a `run` that explorer_export never exported."""
    result = invoke_cli("generate", "explorer")
    assert_json_ok(result)
    exports = tide_corpus_repo / ".opentide" / "exports"
    bundle = exports / "explorer.bundle.json"
    assert bundle.is_file()
    assert (exports / "explorer.search.json").is_file()
    payload = json.loads(bundle.read_text(encoding="utf-8"))
    assert payload["summaries"]


def test_generate_explorer_on_a_fresh_repo(invoke_cli, tmp_path: Path) -> None:
    repo = _fresh_repo(tmp_path, "explorer-fresh")
    assert_json_ok(invoke_cli("generate", "explorer", repo=repo))
    assert (repo / ".opentide" / "exports" / "explorer.bundle.json").is_file()
