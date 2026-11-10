"""CLI E2E: HarfangLab YARA codes in validate, advisories in lint (harfanglab-1.0 1.2)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "harfanglab"
SIGNATURE_RULE = "harfanglab-yara-signature.yaml"


def _add(repo: Path, fixture: str, *, text: str | None = None) -> str:
    """Copy a fixture into the corpus rules; return the name to pass to --file."""
    name = Path(fixture).name
    target = repo / "objects" / "rules" / name
    if text is None:
        shutil.copy(FIXTURES / fixture, target)
    else:
        target.write_text(text, encoding="utf-8")
    return name


def _codes(payload: dict) -> list[str]:
    return [issue["code"] for issue in payload["report"]["issues"]]


def test_a_signature_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    assert_json_ok(invoke_cli("validate", "--file", _add(tide_corpus_repo, SIGNATURE_RULE)))


def test_an_aliased_signature_fails_with_its_code(invoke_cli, tide_corpus_repo: Path) -> None:
    name = _add(tide_corpus_repo, "invalid/rule-yara-signature-alias.yaml")
    result = invoke_cli("validate", "--file", name)
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert "yara_signature_alias" in _codes(payload)
    issue = next(i for i in payload["report"]["issues"] if i["code"] == "yara_signature_alias")
    assert issue["field_path"] == ["configurations", "harfanglab", "yara", "signature"]


@pytest.mark.parametrize(
    ("fixture", "code"),
    [
        ("invalid/rule-harfanglab-sigma-and-yara.yaml", "harfanglab_rule_kind"),
        ("invalid/rule-harfanglab-yara-both-forms.yaml", "harfanglab_yara_form"),
        ("invalid/rule-harfanglab-yara-include.yaml", "yara_include"),
    ],
)
def test_an_invalid_block_fails_validation_with_its_code(
    invoke_cli, tide_corpus_repo: Path, fixture: str, code: str
) -> None:
    result = invoke_cli("validate", "--file", _add(tide_corpus_repo, fixture))
    assert result.exit_code == 1
    assert code in result.output


def test_lint_reports_the_profile_advisories(invoke_cli, tide_corpus_repo: Path) -> None:
    text = (FIXTURES / SIGNATURE_RULE).read_text(encoding="utf-8")
    text = text.replace('context = "file,memory"', 'context = "disk"')
    text = text.replace(
        "        rule Loader_Stage1",
        "        rule No_Meta {\n          condition:\n            true\n        }\n\n"
        "        rule Loader_Stage1",
    )
    name = _add(tide_corpus_repo, SIGNATURE_RULE, text=text)
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", name))
    found = {
        item["code"]: item
        for item in payload["findings"]
        if item["code"] in {"harfanglab_yara_context", "yara_meta_missing"}
    }
    assert set(found) == {"harfanglab_yara_context", "yara_meta_missing"}
    assert all(item["severity"] == "warning" for item in found.values())
    lines = text.splitlines()
    assert "disk" in lines[found["harfanglab_yara_context"]["yaml_line"]]
    assert "rule No_Meta" in lines[found["yara_meta_missing"]["yaml_line"]]


def test_lint_is_quiet_on_the_specification_signature(invoke_cli, tide_corpus_repo: Path) -> None:
    name = _add(tide_corpus_repo, SIGNATURE_RULE)
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", name))
    assert not [
        item
        for item in payload["findings"]
        if item["code"] in {"harfanglab_yara_context", "yara_meta_missing"}
    ]


@pytest.mark.parametrize("code", ["harfanglab_yara_context", "yara_meta_missing"])
def test_explain_has_a_page_for_each_advisory(invoke_cli, code: str) -> None:
    result = invoke_cli("explain", code, json_output=False)
    assert result.exit_code == 0
    assert "## How to fix" in result.output or "How to fix" in result.output
