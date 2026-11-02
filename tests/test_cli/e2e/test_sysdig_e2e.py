"""CLI E2E: the Sysdig platform on the tide_corpus (sysdig-1.0)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import EVERY_RULE

pytestmark = pytest.mark.cli_e2e

UUID = CORPUS_RULE_UUIDS["sysdig"]
RULE = "rule-0013-sysdig-falco.yaml"


def _mock_deployer(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"sysdig": deployer} if "sysdig" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    return deployer


def test_the_corpus_sysdig_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    assert_json_ok(invoke_cli("validate", "--file", RULE))


def test_a_tuning_that_sets_output_fails_validation_with_its_code(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    path = tide_corpus_repo / "objects" / "rules" / RULE
    text = path.read_text(encoding="utf-8").replace(
        "    condition: >\n",
        "    append_to_rule: Terminal shell in container\n    output: replaced\n    condition: >\n",
    )
    path.write_text(text.replace("    tags: [container, shell]\n", ""), encoding="utf-8")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "sysdig_tuning_keys" in result.output


def test_deploy_dry_run_previews_the_api_body_and_the_rules_file(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployer = _mock_deployer(monkeypatch)
    result = invoke_cli(
        "deploy", "--dry-run", "--platform", "sysdig", *EVERY_RULE, "--wide", "--skip-promotion"
    )
    payload = assert_json_ok(result)
    assert UUID in payload["plan"]["sysdig"]
    preview = next(item for item in payload["payloads"]["sysdig"] if item["uuid"] == UUID)
    details = preview["api_request"]["details"]
    assert details["ruleType"] == "FALCO"
    assert details["condition"]["condition"] == (
        "spawned_process and container and proc.name in (bash, sh, zsh)"
    )
    assert details["priority"] == "warning"
    assert "mitre_execution" in preview["api_request"]["tags"]
    (item,) = yaml.safe_load(preview["falco_rules_file"])
    assert item["rule"] == "Sysdig Falco Rule"
    assert item["condition"] == details["condition"]["condition"]
    deployer.deploy.assert_not_called()


def test_validate_query_reports_sysdig_unsupported(invoke_cli) -> None:
    result = invoke_cli("validate", "query", "--platform", "sysdig", "--live")
    payload = parse_cli_json(result)
    assert payload["supported"] is False
    assert payload["platform"] == "sysdig"


def test_query_names_the_platforms_it_supports(invoke_cli) -> None:
    result = invoke_cli("query", "--platform", "sysdig", "evt.type = execve")
    assert result.exit_code == 2
    payload = parse_cli_json(result)
    assert payload["ok"] is False
    assert "sysdig" in payload["message"]
