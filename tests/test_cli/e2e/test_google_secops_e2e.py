"""CLI E2E: the Google Security Operations platform on the tide_corpus (google-secops-1.0)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import EVERY_RULE

from opentide.query.check import LiveCheckReport, RuleCheck

pytestmark = pytest.mark.cli_e2e

UUID = CORPUS_RULE_UUIDS["google_secops"]
RULE = "rule-0015-google-secops-yaral.yaml"


def _rewrite(repo: Path, old: str, new: str) -> None:
    path = repo / "objects" / "rules" / RULE
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def _issues(result: object) -> list[dict[str, object]]:
    payload = parse_cli_json(result)
    report = payload.get("report") or {}
    return list(report.get("issues") or [])


def test_the_corpus_google_secops_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    payload = assert_json_ok(invoke_cli("validate", "--file", RULE))
    assert payload["report"]["warnings"] == []


def test_a_condition_lost_to_a_yaml_comment_fails_at_its_key(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    _rewrite(tide_corpus_repo, "    condition: |\n      $e\n", "    condition: #e > 0\n")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    (issue,) = [item for item in _issues(result) if item["code"] == "yaral_section_empty"]
    assert issue["field_path"] == ["configurations", "google_secops", "condition"]
    assert "YAML comment" in str(issue["message"])


def test_a_pasted_rule_header_fails(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(tide_corpus_repo, "    events: |\n", "    events: |\n      events:\n")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "yaral_section_header" in {item["code"] for item in _issues(result)}


def test_an_aliased_section_fails_with_its_code(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(tide_corpus_repo, "description: |\n", "description: &text |\n")
    _rewrite(tide_corpus_repo, "    condition: |\n      $e\n", "    condition: *text\n")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "yaral_section_alias" in {item["code"] for item in _issues(result)}


def test_the_risk_score_advisory_is_a_warning(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(tide_corpus_repo, "      $risk_score = 70\n", "")
    payload = assert_json_ok(invoke_cli("validate", "--file", RULE))
    codes = {item["code"] for item in payload["report"]["warnings"]}
    assert codes == {"google_secops_risk_score_missing"}
    lint = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", RULE))
    assert "google_secops_risk_score_missing" in {item["code"] for item in lint["findings"]}


def test_two_rules_with_one_name_fail_case_insensitively(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    source = tide_corpus_repo / "objects" / "rules" / RULE
    copy = source.with_name("rule-0016-google-secops-copy.yaml")
    copy.write_text(
        source.read_text(encoding="utf-8")
        .replace(UUID, "00000000-0000-4000-8003-00000000ec02")
        .replace(
            "schema: platform::google_secops::1.0\n",
            "schema: platform::google_secops::1.0\n    name: GOOGLE_SECOPS_YARA_L_RULE\n",
        ),
        encoding="utf-8",
    )
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "google_secops_name_duplicate" in {item["code"] for item in _issues(result)}


def test_deploy_dry_run_previews_the_assembled_rule(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"google_secops": deployer} if "google_secops" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _MockDeployTide)
    result = invoke_cli(
        "deploy",
        "--dry-run",
        "--platform",
        "google_secops",
        *EVERY_RULE,
        "--wide",
        "--skip-promotion",
    )
    payload = assert_json_ok(result)
    assert UUID in payload["plan"]["google_secops"]
    preview = next(item for item in payload["payloads"]["google_secops"] if item["uuid"] == UUID)
    text = preview["api_request"]["text"]
    assert text.startswith("rule google_secops_yara_l_rule {\n  meta:\n")
    assert '    severity = "High"\n' in text
    # T1059.003 is the rule's own; T1059 comes through its detection model.
    assert '    technique = "T1059,T1059.003"\n' in text
    assert f'    opentide_uuid = "{UUID}"\n' in text
    assert text.endswith("  condition:\n    $e\n}\n")
    deployer.deploy.assert_not_called()


def test_validate_query_live_compiles_with_verify_rule_text(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    class _Validator:
        def validate(
            self, mdr_deployment: list[str], strategies: object = None, *, timeout: object = None
        ) -> LiveCheckReport:
            calls.append(list(mdr_deployment))
            return LiveCheckReport(
                "google_secops",
                checks=[
                    RuleCheck(
                        rule=UUID,
                        name="Google SecOps YARA-L Rule",
                        tenant="staging",
                        errors=(
                            "google_secops_compile_error: configurations.google_secops.events "
                            "line 2, column 1: field does not exist",
                        ),
                    )
                ],
            )

    class _Platforms:
        def query_validation_for(self, platform: str) -> dict[str, object]:
            return {"google_secops": _Validator()} if platform == "google_secops" else {}

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _Platforms)
    result = invoke_cli("validate", "query", "--platform", "google_secops", "--live", "--wide")
    assert result.exit_code == 1, result.output
    assert calls and UUID in calls[0]
    payload = parse_cli_json(result)
    assert payload["mode"] == "live" and payload["status"] == "failed"
    assert payload["message"].startswith("Queries rejected on google_secops")


def test_query_rule_is_refused_for_google_secops(invoke_cli) -> None:
    result = invoke_cli("query", "--platform", "google_secops", "--rule", UUID, "--since", "1h")
    assert result.exit_code == 2, result.output
    assert "--rule is not supported for google_secops" in result.output


def test_validate_reports_the_engine_yaral_findings_at_the_section(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    """The offline YARA-L check runs on the sections as the assembled rule."""
    _rewrite(tide_corpus_repo, "metadata.event_type", "metadata.event_typ")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    (issue,) = [item for item in _issues(result) if item["code"] == "yaral_unknown_udm_field"]
    assert issue["field_path"][:3] == ["configurations", "google_secops", "events"]


def test_validate_query_checks_the_corpus_rule_offline(invoke_cli, tide_corpus_repo: Path) -> None:
    payload = assert_json_ok(
        invoke_cli("validate", "query", "--platform", "google_secops", "--file", RULE)
    )
    assert [item["language"] for item in payload["queries"]] == ["yaral"]


@pytest.mark.parametrize("suffix", [".yaral", ".yl2"])
def test_validate_query_checks_a_yaral_file(
    invoke_cli, tide_corpus_repo: Path, tmp_path: Path, suffix: str
) -> None:
    rule = (
        'rule logins {\n  meta:\n    author = "a"\n\n  events:\n'
        '    $e.metadata.event_type = "USER_LOGIN"\n\n  outcome:\n    $risk_score = 40\n\n'
        "  condition:\n    $e\n}\n"
    )
    good = tmp_path / f"good{suffix}"
    good.write_text(rule)
    assert_json_ok(invoke_cli("validate", "query", "--file", str(good)))
    bad = tmp_path / f"bad{suffix}"
    bad.write_text(rule.replace("USER_LOGIN", "USER_LOGGED_IN"))
    result = invoke_cli("validate", "query", "--file", str(bad))
    assert result.exit_code == 1
    assert "yaral_enum_value" in result.output


def test_lint_reports_each_advisory_once(invoke_cli, tide_corpus_repo: Path) -> None:
    """The engine reports the block's advisories too; lint shows each once."""
    _rewrite(tide_corpus_repo, "      $risk_score = 70\n", "")
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", RULE))
    codes = [item["code"] for item in payload["findings"]]
    assert codes.count("google_secops_risk_score_missing") == 1
