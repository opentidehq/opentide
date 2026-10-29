"""CLI E2E: a rule block for a platform the workspace has not enabled (#410, #413).

The block is legal: rules travel between repositories, and the generated
schema already accepts every registered platform. ``validate`` reports it as a
``platform_not_enabled`` warning so the author knows it will not deploy. The
warning must not fail ``--strict``, which the commit hook and generated CI run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

SPLUNK_RULE = "objects/rules/rule-0003-splunk-spl.yaml"
SPLUNK_RULE_UUID = "00000000-0000-4000-8003-000000000003"
SPLUNK_CONFIG = ".opentide/configurations/systems/splunk.toml"


@pytest.fixture
def splunk_disabled(tide_corpus_repo: Path) -> Path:
    config = tide_corpus_repo / SPLUNK_CONFIG
    text = config.read_text(encoding="utf-8")
    assert "[tide]\nenabled = true\n" in text
    config.write_text(
        text.replace("[tide]\nenabled = true\n", "[tide]\nenabled = false\n"), encoding="utf-8"
    )
    return tide_corpus_repo


def _platform_warnings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [w for w in payload["report"]["warnings"] if w["code"] == "platform_not_enabled"]


def _edit_splunk_rule(repo: Path, old: str, new: str) -> None:
    rule = repo / SPLUNK_RULE
    text = rule.read_text(encoding="utf-8")
    assert old in text
    rule.write_text(text.replace(old, new), encoding="utf-8")


@pytest.mark.usefixtures("splunk_disabled")
@pytest.mark.parametrize("strict", [False, True], ids=["default", "strict"])
def test_disabled_platform_block_passes_with_a_warning(invoke_cli, strict: bool) -> None:
    args = ("validate", "--strict") if strict else ("validate",)
    payload = assert_json_ok(invoke_cli(*args))
    assert payload["status"] == "passed"
    assert payload["report"]["ok"] is True
    (warning,) = _platform_warnings(payload)
    assert warning["severity"] == "warning"
    assert warning["object_uuid"] == SPLUNK_RULE_UUID
    assert warning["field_path"] == ["configurations", "splunk"]
    assert warning["context"] == {"platform": "splunk"}
    assert warning["file_path"].endswith("rule-0003-splunk-spl.yaml")
    # Like every issue on a mapping, the line is the block's first, under its key.
    lines = Path(warning["file_path"]).read_text(encoding="utf-8").splitlines()
    assert lines[warning["yaml_line"] - 1] == "  splunk:"
    assert "opentide setup platforms --splunk" in warning["message"]
    assert payload["warnings"] == [
        f"{warning['file_path']}:{warning['yaml_line'] + 1}: "
        f"configurations.splunk: {warning['message']}"
    ]


def test_enabled_platform_block_does_not_warn(invoke_cli) -> None:
    payload = assert_json_ok(invoke_cli("validate", "--strict"))
    assert _platform_warnings(payload) == []
    assert "warnings" not in payload


@pytest.mark.usefixtures("splunk_disabled")
def test_human_output_names_the_disabled_platform(invoke_cli) -> None:
    result = invoke_cli("validate", "--strict", json_output=False)
    assert result.exit_code == 0, result.stdout + result.stderr
    output = " ".join((result.stdout + result.stderr).split())
    assert "warning[platform_not_enabled]: this block will not deploy while splunk" in output
    assert "rule-0003-splunk-spl.yaml:23:3" in output
    assert "opentide setup platforms --splunk" in output
    assert re.search(r" valid · \d+ quer(y|ies) · 1 warning · ", output), output
    # The frame is the warning; it is not printed a second time as a warning line.
    assert "warning: " not in output


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        pytest.param(
            "    search: index=main | head 1\n",
            '    query: ""\n',
            "query must not be empty",
            id="empty-query",
        ),
        pytest.param("  splunk:\n", "  splnk:\n", "splnk", id="unknown-platform"),
        pytest.param(
            "    status: STAGING\n",
            "    status: STAGING\n    unknown_key: true\n",
            "unknown_key",
            id="unknown-key",
        ),
    ],
)
def test_malformed_block_still_fails_when_its_platform_is_disabled(
    invoke_cli, splunk_disabled: Path, old: str, new: str, expected: str
) -> None:
    _edit_splunk_rule(splunk_disabled, old, new)
    result = invoke_cli("validate")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    messages = " ".join(
        f"{'.'.join(issue['field_path'])} {issue['message']}"
        for issue in payload["report"]["issues"]
    )
    assert expected in messages


_SENTINEL_BLOCK = """\
  sentinel:
    enabled: true
    name: Splunk SPL Rule
    status: STAGING
    query: {query}
    scheduling:
      frequency: PT1H
      lookback: PT2H
    alert:
      title: Splunk SPL Rule
"""


@pytest.mark.usefixtures("splunk_disabled")
def test_two_platform_rule_warns_once_for_the_disabled_one(
    invoke_cli, splunk_disabled: Path
) -> None:
    _edit_splunk_rule(
        splunk_disabled,
        "configurations:\n",
        "configurations:\n" + _SENTINEL_BLOCK.format(query="SecurityEvent | take 1"),
    )
    payload = assert_json_ok(invoke_cli("validate", "--strict"))
    (warning,) = _platform_warnings(payload)
    assert warning["field_path"] == ["configurations", "splunk"]


@pytest.mark.usefixtures("splunk_disabled")
def test_two_platform_rule_still_validates_the_enabled_block(
    invoke_cli, splunk_disabled: Path
) -> None:
    _edit_splunk_rule(
        splunk_disabled,
        "configurations:\n",
        "configurations:\n" + _SENTINEL_BLOCK.format(query='""'),
    )
    result = invoke_cli("validate")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    (issue,) = payload["report"]["issues"]
    assert issue["field_path"][:3] == ["configurations", "sentinel", "query"]
    assert len(_platform_warnings(payload)) == 1


def test_live_query_validation_of_a_disabled_platform_names_a_working_flag(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    """#414: live validation stays gated; its advice named ``--defender_for_endpoint``."""
    config = tide_corpus_repo / ".opentide/configurations/systems/defender_for_endpoint.toml"
    text = config.read_text(encoding="utf-8")
    assert "[platform]\nenabled = true\n" in text
    config.write_text(text.replace("enabled = true", "enabled = false", 1), encoding="utf-8")
    result = invoke_cli(
        "validate", "query", "--platform", "defender_for_endpoint", "--live", "--wide"
    )
    payload = assert_json_ok(result)
    assert payload["status"] == "skipped"
    assert payload["platform_enabled"] is False
    assert payload["advice"] == "enable it with 'opentide setup platforms --defender-for-endpoint'"


@pytest.mark.parametrize("typo", ["enabeld", "Enabled", "enable"])
def test_a_misspelled_enabled_key_is_named_instead_of_setup_platforms(
    invoke_cli, tide_corpus_repo: Path, typo: str
) -> None:
    """``enabeld = true`` left splunk disabled, and the warning sent the author to
    ``opentide setup platforms --splunk`` (post-merge end-to-end run)."""
    config = tide_corpus_repo / SPLUNK_CONFIG
    text = config.read_text(encoding="utf-8")
    config.write_text(
        text.replace("[tide]\nenabled = true\n", f"[tide]\n{typo} = true\n"), encoding="utf-8"
    )
    payload = assert_json_ok(invoke_cli("validate"))
    (warning,) = _platform_warnings(payload)
    assert warning["context"] == {"platform": "splunk", "key": typo}
    assert warning["message"] == (
        f"this block will not deploy: {SPLUNK_CONFIG} sets '{typo}' in [tide], not "
        "'enabled', so splunk is disabled; rename the key to 'enabled'"
    )
