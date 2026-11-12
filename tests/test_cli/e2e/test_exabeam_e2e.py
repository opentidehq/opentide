"""CLI E2E: the Exabeam New-Scale SIEM platform on the tide_corpus (exabeam-1.0)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import EVERY_RULE

pytestmark = pytest.mark.cli_e2e

UUID = CORPUS_RULE_UUIDS["exabeam"]
RULE = "rule-0015-exabeam-correlation.yaml"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "exabeam"


def _mock_deployer(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"exabeam": deployer} if "exabeam" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _MockDeployTide)
    return deployer


def _rule_path(repo: Path) -> Path:
    return repo / "objects" / "rules" / RULE


def _rewrite(repo: Path, old: str, new: str) -> None:
    path = _rule_path(repo)
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def _codes(result: object) -> set[str]:
    """The codes of a ``validate --json`` run's issues and warnings."""
    report = parse_cli_json(result)["report"]  # type: ignore[arg-type]
    return {item["code"] for item in [*report.get("issues", []), *report.get("warnings", [])]}


def test_the_corpus_exabeam_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    assert_json_ok(invoke_cli("validate", "--file", RULE))


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        ("          within: 30m\n", "          within: 1h30m\n", "exabeam_duration"),
        (
            "          operator: more_than\n",
            "          operator: in\n",
            "exabeam_threshold_operator",
        ),
        ("    outcome: case\n", "    outcome: Case\n", "exabeam_outcome"),
        (
            '          activity_type:"app-login" AND outcome:"fail"\n',
            '          activity_type:"app-login" AND user IN "Admins"\n',
            "exabeam_context_table_trigger",
        ),
    ],
)
def test_a_broken_block_fails_with_its_code(
    invoke_cli, tide_corpus_repo: Path, old: str, new: str, code: str
) -> None:
    _rewrite(tide_corpus_repo, old, new)
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert code in _codes(result)


def test_a_silent_outcome_is_a_warning(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(tide_corpus_repo, "    outcome: case\n", "    outcome: none\n")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 0
    assert "exabeam_outcome_silent" in _codes(result)


def test_two_rules_with_one_exabeam_name_fail(invoke_cli, tide_corpus_repo: Path) -> None:
    source = _rule_path(tide_corpus_repo)
    copy = source.with_name("rule-0016-exabeam-copy.yaml")
    copy.write_text(
        source.read_text(encoding="utf-8")
        .replace(UUID, "00000000-0000-4000-8003-0000e8ab0002")
        .replace("name: Exabeam Correlation Rule", "name: EXABEAM correlation rule"),
        encoding="utf-8",
    )
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "exabeam_name_duplicate" in _codes(result)


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("rule-exabeam-correlation-single.yaml", "exabeam_correlation"),
        ("rule-exabeam-threshold-operator.yaml", "exabeam_threshold_operator"),
        ("rule-exabeam-context-table-threshold.yaml", "exabeam_context_table_trigger"),
        ("rule-exabeam-delay.yaml", "exabeam_duration"),
    ],
)
def test_the_specification_invalid_fixtures_fail_with_their_code(
    invoke_cli, tide_corpus_repo: Path, name: str, code: str
) -> None:
    shutil.copy(FIXTURES / "invalid" / name, tide_corpus_repo / "objects" / "rules" / name)
    result = invoke_cli("validate", "--file", name)
    assert result.exit_code == 1
    assert code in _codes(result)


def test_deploy_dry_run_previews_the_create_request(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployer = _mock_deployer(monkeypatch)
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "exabeam",
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert UUID in payload["plan"]["exabeam"]
    preview = next(item for item in payload["payloads"]["exabeam"] if item["uuid"] == UUID)
    request = preview["api_request"]
    assert (request["method"], request["path"]) == ("POST", "/correlation-rules/v2/rules")
    body = request["body"]
    assert body["name"] == "Exabeam Correlation Rule"
    assert body["severity"] == "high"
    assert body["enabled"] is True
    # The corpus tenant runs every rule in test mode; the preview names it.
    assert body["testMode"] is True
    assert preview["tenant"] == "staging"
    assert "ATT&CK: T1059.005" in body["description"]
    assert body["description"].endswith(f"opentide: {UUID}")
    assert body["sequencesConfig"]["outcomes"]["createCase"] is True
    assert json.dumps(body)  # serialisable as the deploy sends it
    deployer.deploy.assert_not_called()


def test_validate_query_live_is_supported_for_exabeam(invoke_cli) -> None:
    """--live reaches Search; with no credentials the tenant fails, never a fake pass."""
    result = invoke_cli("validate", "query", "--platform", "exabeam", "--live")
    payload = parse_cli_json(result)
    assert payload["supported"] is True
    assert payload["platform"] == "exabeam"
    assert payload["status"] == "failed"
    assert result.exit_code != 0


def test_setup_platforms_enables_exabeam(invoke_cli, tmp_path: Path) -> None:
    assert_json_ok(invoke_cli("setup", "platforms", str(tmp_path), "--exabeam", "--yes"))
    written = tmp_path / ".opentide" / "configurations" / "platforms" / "exabeam.toml"
    assert "enabled = true" in written.read_text(encoding="utf-8")
