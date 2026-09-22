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
from tests.test_cli.e2e.helpers import hidden_modules

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
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
    repo = _fresh_repo(tmp_path, "extract-extra")
    purge = ("opentide.extraction.sentinel_importer", "opentide.platforms.sentinel")
    with hidden_modules("azure", purge=purge):
        result = invoke_cli("generate", "extract", "sentinel", repo=repo)
    message = parse_cli_json(result)["error"]
    assert "opentide[sentinel]" in message
    assert "Extraction module not found" not in message


def test_generate_extract_defender_reports_unconfigured_tenants(invoke_cli, tmp_path: Path) -> None:
    """The old dummy tenant raised `KeyError: ''` before the CLI could speak."""
    repo = _fresh_repo(tmp_path, "extract-defender-tenants")
    result = invoke_cli("generate", "extract", "defender", repo=repo)
    assert "tenants" in parse_cli_json(result)["error"]


DEFENDER_TENANT = """
[[tenants]]
name = "Contoso"
description = "Test tenant"
deployment = "ALWAYS"
[tenants.setup]
proxy = false
ssl = true
tenant_id = "tid"
client_id = "cid"
client_secret = "secret"
[tenants.parameters]
device_groups = ["all"]
"""

DEFENDER_TENANT_WITHOUT_CREDENTIALS = """
[[tenants]]
name = "Contoso"
description = "Test tenant"
deployment = "ALWAYS"
[tenants.setup]
tenant_id = "tid"
"""


def _repo_with_platform(tmp_path: Path, name: str, platform: DetectionPlatform) -> Path:
    repo = tmp_path / name
    run_repo_setup(RepoSetupOptions(path=repo, name=name, yes=True, platforms=[platform]))
    run_platforms_setup(PlatformsSetupOptions(path=repo, platforms=[platform], yes=True))
    return repo


def _configure_tenant(repo: Path, platform: DetectionPlatform, fragment: str) -> None:
    config = repo / ".opentide" / "configurations" / "platforms" / f"{platform.value}.toml"
    text = config.read_text(encoding="utf-8").replace("enabled = false", "enabled = true")
    config.write_text(text + fragment, encoding="utf-8")


def test_generate_extract_defender_with_a_configured_tenant_stays_structured(
    invoke_cli, tmp_path: Path
) -> None:
    """Issue #242 also hid behind "no tenants".

    ``build_system_config`` only built typed tenants for Splunk and Carbon
    Black, so the first configured Defender tenant reached
    ``DefenderForEndpointImporter(tenant)`` as a plain dict and died on
    ``tenant.setup.proxy`` — an ``AttributeError`` that escaped as a Rich
    traceback with empty stdout, which is exactly the #242 symptom.
    """
    repo = _repo_with_platform(tmp_path, "extract-defender-configured", DetectionPlatform.defender)
    _configure_tenant(repo, DetectionPlatform.defender, DEFENDER_TENANT)
    result = invoke_cli("generate", "extract", "defender", repo=repo)
    combined = result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["ok"] is False
    assert "AttributeError" not in combined, combined
    assert "Traceback" not in combined, combined


def test_a_half_configured_tenant_names_the_missing_key(invoke_cli, tmp_path: Path) -> None:
    """A TOML typo must name the key, not raise a positional-argument TypeError."""
    repo = _repo_with_platform(tmp_path, "extract-defender-partial", DetectionPlatform.defender)
    _configure_tenant(repo, DetectionPlatform.defender, DEFENDER_TENANT_WITHOUT_CREDENTIALS)
    result = invoke_cli("generate", "extract", "defender", repo=repo)
    message = parse_cli_json(result)["error"]
    assert "Contoso" in message
    assert "client_id" in message
    assert "client_secret" in message


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
