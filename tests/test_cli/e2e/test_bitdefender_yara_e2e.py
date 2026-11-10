"""CLI E2E: Bitdefender's yara.signature is checked offline under the engine's bitdefender
profile (bitdefender-1.0, yara-1.0): each code once, at its line, in validate and lint.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "bitdefender"
SIGNATURE_RULE = "rule-bitdefender-yara-1.0.yaml"
SIGNATURE = ["configurations", "bitdefender", "yara", "signature"]
#: The line of the fixture's signature the replacements below edit.
CONDITION = "            MZ_Header and pe.number_of_sections > 3 and all of them"


def _add(repo: Path, *, text: str | None = None) -> str:
    """Copy the signature fixture (or *text*) into the corpus rules; return its name."""
    target = repo / "objects" / "rules" / SIGNATURE_RULE
    if text is None:
        shutil.copy(FIXTURES / SIGNATURE_RULE, target)
    else:
        target.write_text(text, encoding="utf-8")
    return SIGNATURE_RULE


def _fixture() -> str:
    return (FIXTURES / SIGNATURE_RULE).read_text(encoding="utf-8")


def _with_include() -> str:
    return _fixture().replace(
        '        import "pe"', '        include "other.yar"\n        import "pe"'
    )


def _non_ascii() -> str:
    return _fixture().replace(
        'description = "Stage-1 loader', 'description = "Stage-1 loader \N{EM DASH}'
    )


def _oversize() -> str:
    filler = "".join(f"        // padding line {n:05d} {'x' * 60}\n" for n in range(450))
    return _fixture().replace(
        "        private rule MZ_Header", filler + "        private rule MZ_Header"
    )


def _codes(payload: dict, *, warnings: bool = False) -> list[str]:
    key = "warnings" if warnings else "issues"
    return [issue["code"] for issue in payload["report"][key]]


def _validate(invoke_cli, repo: Path, text: str, *extra: str) -> dict:
    result = invoke_cli("validate", "--file", _add(repo, text=text), *extra)
    assert result.exit_code == 1, result.output
    return parse_cli_json(result)


def test_the_specification_signature_is_clean(invoke_cli, tide_corpus_repo: Path) -> None:
    payload = assert_json_ok(invoke_cli("validate", "--file", _add(tide_corpus_repo)))
    assert payload["report"]["stats"]["queries_checked"] == 1
    assert not [code for code in _codes(payload, warnings=True) if "yara" in code]


def test_lint_is_quiet_on_the_specification_signature(invoke_cli, tide_corpus_repo: Path) -> None:
    payload = parse_cli_json(
        invoke_cli("lint", "--check", "queries", "--file", _add(tide_corpus_repo))
    )
    assert not [item for item in payload["findings"] if "yara" in item["code"]]


def test_an_include_is_reported_once_at_its_line(invoke_cli, tide_corpus_repo: Path) -> None:
    text = _with_include()
    payload = _validate(invoke_cli, tide_corpus_repo, text)
    assert _codes(payload).count("yara_include") == 1
    issue = next(i for i in payload["report"]["issues"] if i["code"] == "yara_include")
    assert issue["field_path"][:4] == SIGNATURE
    assert issue["context"]["source"] == "engine"
    assert text.splitlines()[issue["line"] - 1].strip() == 'include "other.yar"'


@pytest.mark.parametrize(
    ("text", "code"),
    [(_non_ascii, "bitdefender_yara_ascii"), (_oversize, "bitdefender_yara_size")],
)
def test_a_profile_limit_is_reported_once(
    invoke_cli, tide_corpus_repo: Path, text, code: str
) -> None:
    """The engine's finding, at its place in the signature, replaces the model's."""
    source = text()
    payload = _validate(invoke_cli, tide_corpus_repo, source)
    assert _codes(payload).count(code) == 1
    assert code not in _codes(payload, warnings=True)
    issue = next(i for i in payload["report"]["issues"] if i["code"] == code)
    assert issue["context"]["source"] == "engine"
    assert issue["field_path"][:4] == SIGNATURE
    if code == "bitdefender_yara_ascii":
        assert "\N{EM DASH}" in source.splitlines()[issue["line"] - 1]


@pytest.mark.parametrize("text", [_with_include, _non_ascii, _oversize])
def test_warn_mode_keeps_the_models_error_and_drops_the_engines(
    invoke_cli, tide_corpus_repo: Path, text
) -> None:
    """--queries warn: the model's error still fails the rule, as deploy would; once."""
    payload = _validate(invoke_cli, tide_corpus_repo, text(), "--queries", "warn")
    every = _codes(payload) + _codes(payload, warnings=True)
    codes = [code for code in every if code.startswith(("yara_", "bitdefender_yara_"))]
    assert len(codes) == 1
    assert codes[0] in _codes(payload)


def test_a_syntax_error_the_model_misses_comes_from_the_engine(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    text = _fixture().replace(CONDITION, "            MZ_Header and and")
    payload = _validate(invoke_cli, tide_corpus_repo, text)
    issue = next(i for i in payload["report"]["issues"] if i["code"] == "yara_parse_error")
    assert issue["field_path"][:4] == SIGNATURE


@pytest.mark.parametrize("text", [_with_include, _non_ascii, _oversize])
def test_lint_leaves_the_errors_to_validate(invoke_cli, tide_corpus_repo: Path, text) -> None:
    """A signature the profile rejects is validate's finding, never lint's too."""
    name = _add(tide_corpus_repo, text=text())
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", name))
    assert not [item for item in payload["findings"] if "yara" in item["code"]]


def _unconfirmed_module() -> str:
    return _fixture().replace('        import "pe"', '        import "pe"\n        import "dotnet"')


def test_an_unconfirmed_module_is_a_lint_warning_once(invoke_cli, tide_corpus_repo: Path) -> None:
    """The profile's confirmed modules: another known module is a warning (bitdefender-1.0)."""
    text = _unconfirmed_module()
    name = _add(tide_corpus_repo, text=text)
    payload = parse_cli_json(invoke_cli("lint", "--check", "queries", "--file", name))
    found = [item for item in payload["findings"] if item["code"] == "yara_module_unconfirmed"]
    assert len(found) == 1
    assert found[0]["severity"] == "warning"
    assert 'import "dotnet"' in text.splitlines()[found[0]["yaml_line"]]


def test_an_unconfirmed_module_does_not_fail_validate(invoke_cli, tide_corpus_repo: Path) -> None:
    """The warning is lint's style finding; validate checks the signature, once."""
    payload = assert_json_ok(
        invoke_cli("validate", "--file", _add(tide_corpus_repo, text=_unconfirmed_module()))
    )
    assert payload["report"]["stats"]["queries_checked"] == 1


def test_validate_query_checks_a_file_offline(invoke_cli, tmp_path: Path) -> None:
    query = tmp_path / "x.yar"
    query.write_text('include "a.yar"\nrule A {\n  condition:\n    true // é\n}\n', "utf-8")
    payload = parse_cli_json(
        invoke_cli("validate", "query", "--file", str(query), "--platform", "bitdefender")
    )
    assert payload["mode"] == "offline"
    codes = {item["code"] for item in payload["diagnostics"]}
    assert {"yara_include", "bitdefender_yara_ascii"} <= codes


def test_live_is_not_supported(invoke_cli) -> None:
    result = invoke_cli("validate", "query", "--platform", "bitdefender", "--live")
    payload = parse_cli_json(result)
    assert payload["supported"] is False
    assert payload["valid"] is None
