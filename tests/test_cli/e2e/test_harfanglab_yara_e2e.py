"""CLI E2E: HarfangLab YARA codes in validate, advisories in lint (harfanglab-1.0 1.2)."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import hidden_modules

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


ADVISORIES = {"harfanglab_yara_context", "yara_meta_missing"}


def _bad_signature() -> str:
    """The signature fixture with a bad hex string and an unknown module."""
    text = (FIXTURES / SIGNATURE_RULE).read_text(encoding="utf-8")
    return text.replace("43 46 47 21", "4G 46").replace('import "pe"', 'import "nosuchmodule"')


def test_validate_checks_the_signature_as_yara(invoke_cli, tide_corpus_repo: Path) -> None:
    """harfanglab-1.0: yara.signature is checked against the YARA language; errors fail."""
    name = _add(tide_corpus_repo, SIGNATURE_RULE, text=_bad_signature())
    result = invoke_cli("validate", "--file", name)
    assert result.exit_code == 1
    codes = _codes(parse_cli_json(result))
    assert {"yara_hex_string", "yara_unknown_module"} <= set(codes)


def test_validate_checks_the_decomposed_rule_as_yara(invoke_cli, tide_corpus_repo: Path) -> None:
    text = (FIXTURES / "harfanglab-yara.yaml").read_text(encoding="utf-8")
    text = text.replace('$a = "cmd.exe" ascii', "$a = { 4G 46 }")
    result = invoke_cli(
        "validate", "--file", _add(tide_corpus_repo, "harfanglab-yara.yaml", text=text)
    )
    assert result.exit_code == 1
    assert "yara_hex_string" in _codes(parse_cli_json(result))


@pytest.mark.parametrize("fixture", [SIGNATURE_RULE, "harfanglab-yara.yaml"])
def test_the_specification_yara_fixtures_pass_the_yara_check(
    invoke_cli, tide_corpus_repo: Path, fixture: str
) -> None:
    payload = assert_json_ok(
        invoke_cli("validate", "--check", "queries", "--file", _add(tide_corpus_repo, fixture))
    )
    assert payload["report"]["stats"]["queries_checked"] == 1


@pytest.mark.parametrize("suffix", [".yar", ".yara"])
def test_validate_query_checks_a_yara_file(
    invoke_cli, tide_corpus_repo: Path, tmp_path: Path, suffix: str
) -> None:
    good = tmp_path / f"good{suffix}"
    good.write_text('rule a {\n  meta:\n    context = "file"\n  condition:\n    true\n}\n')
    assert_json_ok(invoke_cli("validate", "query", "--file", str(good)))
    bad = tmp_path / f"bad{suffix}"
    bad.write_text("rule a {\n  strings:\n    $a = { 4G }\n  condition:\n    $a\n}\n")
    result = invoke_cli("validate", "query", "--file", str(bad))
    assert result.exit_code == 1
    assert "yara_hex_string" in result.output


def test_validate_query_harfanglab_live_is_unsupported(invoke_cli) -> None:
    payload = parse_cli_json(invoke_cli("validate", "query", "--platform", "harfanglab", "--live"))
    assert payload["supported"] is False


def test_lint_reports_each_advisory_once(invoke_cli, tide_corpus_repo: Path) -> None:
    """The engine reports the profile advisories too; lint shows each once."""
    text = (FIXTURES / SIGNATURE_RULE).read_text(encoding="utf-8")
    text = text.replace('context = "file,memory"', 'context = "disk"')
    name = _add(tide_corpus_repo, SIGNATURE_RULE, text=text)
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", name))
    assert [item["code"] for item in payload["findings"] if item["code"] in ADVISORIES] == [
        "harfanglab_yara_context"
    ]


@pytest.fixture
def no_engine() -> Iterator[None]:
    """The engine does not import, as in a damaged install."""
    from opentide.analysis import engine

    engine.cache_clear()
    with hidden_modules("opentide._native", purge=("opentide._native",)):
        yield
    engine.cache_clear()


def test_lint_reports_the_advisories_without_the_engine(
    invoke_cli, tide_corpus_repo: Path, no_engine: None
) -> None:
    text = (FIXTURES / SIGNATURE_RULE).read_text(encoding="utf-8")
    text = text.replace('context = "file,memory"', 'context = "disk"')
    name = _add(tide_corpus_repo, SIGNATURE_RULE, text=text)
    result = invoke_cli("lint", "--check", "queries", "--file", name)
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload["failure"]["code"] == "engine_unavailable"
    assert [item["code"] for item in payload["findings"]] == ["harfanglab_yara_context"]
    assert "disk" in text.splitlines()[payload["findings"][0]["yaml_line"]]
