"""CLI E2E: ``validate`` fails a rule a platform compiler cannot build (#660).

A rule that validates must deploy: ``validate`` runs the compiler a deploy
dry run runs, on each rule a deploy would compile, and reports its error with
the same code, message and help.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

SENTINEL_RULE = "objects/rules/rule-0001-sentinel-kql.yaml"
SENTINEL_RULE_UUID = "00000000-0000-4000-8003-000000000001"
SENTINEL_CONFIG = ".opentide/configurations/systems/sentinel.toml"
GROUPING_ALERT = "      alert:\n        enabled: false\n"


def _edit(repo: Path, old: str, new: str) -> None:
    rule = repo / SENTINEL_RULE
    text = rule.read_text(encoding="utf-8")
    assert old in text
    rule.write_text(text.replace(old, new, 1), encoding="utf-8")


def _compile_issues(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [i for i in payload["report"]["issues"] if i["code"].startswith("compile_")]


def _failing_validate(invoke_cli) -> dict[str, Any]:
    result = invoke_cli("validate")
    assert result.exit_code == 1, result.stdout + result.stderr
    return parse_cli_json(result)


def test_missing_grouping_alert_fails_validate_like_the_dry_run(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    _edit(tide_corpus_repo, GROUPING_ALERT, "")
    (issue,) = _compile_issues(_failing_validate(invoke_cli))
    assert issue["code"] == "compile_missing_field"
    assert issue["object_uuid"] == SENTINEL_RULE_UUID
    assert issue["message"] == "configurations.sentinel.grouping.alert is missing"
    assert issue["field_path"] == ["configurations", "sentinel", "grouping", "alert"]
    assert issue["context"] == {"platform": "sentinel"}
    # The key is missing, so the frame is the block that should hold it.
    lines = (tide_corpus_repo / SENTINEL_RULE).read_text(encoding="utf-8").splitlines()
    assert lines[issue["line"] - 1] == "    grouping:"
    assert issue["yaml_line"] == issue["line"] - 1

    plan = parse_cli_json(invoke_cli("deploy", "--dry-run", "--strategy", "PREVIEW", "--all"))
    (diagnostic,) = [d for d in plan["diagnostics"] if d["code"] == "compile_missing_field"]
    assert (diagnostic["message"], diagnostic["help"]) == (issue["message"], issue["help"])


def test_missing_frequency_fails_unless_the_rule_is_nrt(invoke_cli, tide_corpus_repo: Path) -> None:
    _edit(tide_corpus_repo, "      frequency: PT1H\n", "")
    (issue,) = _compile_issues(_failing_validate(invoke_cli))
    assert issue["field_path"] == ["configurations", "sentinel", "scheduling", "frequency"]
    assert issue["help"] == "required unless scheduling.nrt is true"

    _edit(tide_corpus_repo, "    scheduling:\n", "    scheduling:\n      nrt: true\n")
    assert_json_ok(invoke_cli("validate", "--strict"))


@pytest.mark.parametrize("status", ["DESIGN", "REMOVED"])
def test_a_rule_deploy_does_not_compile_is_not_compiled(
    invoke_cli, tide_corpus_repo: Path, status: str
) -> None:
    """An inert rule is never sent and a removed one is deleted by its vendor id."""
    _edit(tide_corpus_repo, GROUPING_ALERT, "")
    _edit(tide_corpus_repo, "    status: STAGING\n", f"    status: {status}\n")
    payload = invoke_cli("validate")
    assert not _compile_issues(parse_cli_json(payload))


def test_a_disabled_platform_is_not_compiled(invoke_cli, tide_corpus_repo: Path) -> None:
    config = tide_corpus_repo / SENTINEL_CONFIG
    text = config.read_text(encoding="utf-8")
    assert "enabled = true" in text
    config.write_text(text.replace("enabled = true", "enabled = false"), encoding="utf-8")
    _edit(tide_corpus_repo, GROUPING_ALERT, "")
    assert not _compile_issues(parse_cli_json(invoke_cli("validate")))


def test_suppression_true_is_reported_at_the_key(invoke_cli, tide_corpus_repo: Path) -> None:
    _edit(tide_corpus_repo, "      suppression: false\n", "      suppression: true\n")
    (issue,) = _compile_issues(_failing_validate(invoke_cli))
    assert issue["code"] == "compile_invalid_value"
    assert issue["field_path"] == ["configurations", "sentinel", "alert", "suppression"]
    lines = (tide_corpus_repo / SENTINEL_RULE).read_text(encoding="utf-8").splitlines()
    assert lines[issue["line"] - 1] == "      suppression: true"
