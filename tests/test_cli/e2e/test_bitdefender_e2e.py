"""CLI E2E: the Bitdefender GravityZone platform on the tide_corpus (bitdefender-1.0)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import EVERY_RULE

pytestmark = pytest.mark.cli_e2e

UUID = CORPUS_RULE_UUIDS["bitdefender"]
RULE = "rule-0014-bitdefender-gravityzone.yaml"


def _mock_deployer(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"bitdefender": deployer} if "bitdefender" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _MockDeployTide)
    return deployer


def _rewrite(repo: Path, old: str, new: str) -> None:
    path = repo / "objects" / "rules" / RULE
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_the_corpus_bitdefender_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    assert_json_ok(invoke_cli("validate", "--file", RULE))


def test_a_field_the_target_lacks_fails_with_its_code(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(tide_corpus_repo, "field: Process.CommandLine", "field: Process.Hash")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "bitdefender_criterion_field" in result.output


def test_an_aliased_yara_signature_fails_with_its_code(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(
        tide_corpus_repo,
        "description: |\n",
        "description: &sig |\n",
    )
    _rewrite(
        tide_corpus_repo,
        "    detection:\n      target: process\n      criteria:\n"
        "        - field: Process.Parent.Name\n          any: [winword.exe, excel.exe]\n"
        '        - field: Process.CommandLine\n          contains: "*-enc*"\n',
        "    yara:\n      signature: *sig\n",
    )
    _rewrite(
        tide_corpus_repo, "      kill_process: {include_children: true}\n", "      isolate: true\n"
    )
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "yara_signature_alias" in result.output


def test_two_rules_with_one_gravityzone_name_fail(invoke_cli, tide_corpus_repo: Path) -> None:
    source = tide_corpus_repo / "objects" / "rules" / RULE
    copy = source.with_name("rule-0015-bitdefender-copy.yaml")
    copy.write_text(
        source.read_text(encoding="utf-8").replace(
            "00000000-0000-4000-8003-0000b1d0f001", "00000000-0000-4000-8003-0000b1d0f002"
        ),
        encoding="utf-8",
    )
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "bitdefender_name_duplicate" in result.output


def test_deploy_dry_run_previews_the_create_request(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployer = _mock_deployer(monkeypatch)
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "bitdefender",
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert UUID in payload["plan"]["bitdefender"]
    preview = next(item for item in payload["payloads"]["bitdefender"] if item["uuid"] == UUID)
    request = preview["api_request"]
    assert request["method"] == "createCustomRule"
    params = request["params"]
    assert (params["type"], params["subtype"], params["returnRuleId"]) == (1, 0, True)
    assert params["name"] == "Bitdefender GravityZone Rule"
    assert params["settings"]["severity"] == 3
    assert "T1059.005" in params["tags"]
    assert f"opentide:{UUID}" in params["tags"]
    deployer.deploy.assert_not_called()


def test_validate_query_reports_bitdefender_unsupported(invoke_cli) -> None:
    for extra in ((), ("--live",)):
        result = invoke_cli("validate", "query", "--platform", "bitdefender", *extra)
        payload = parse_cli_json(result)
        assert payload["supported"] is False
        assert payload["platform"] == "bitdefender"


def test_setup_platforms_enables_bitdefender(invoke_cli, tmp_path: Path) -> None:
    assert_json_ok(invoke_cli("setup", "platforms", str(tmp_path), "--bitdefender", "--yes"))
    written = tmp_path / ".opentide" / "configurations" / "platforms" / "bitdefender.toml"
    assert "enabled = true" in written.read_text(encoding="utf-8")
