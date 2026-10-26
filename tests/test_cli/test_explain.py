"""``opentide explain``: a page for every code the CLI emits, and the generated reference."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.explain import (
    REFERENCE_PAGE,
    diagnostic_codes,
    load_page,
    reference_markdown,
)
from opentide.cli.services.validation import VALIDATION_CODES
from opentide.cli.ui.diagnostics import LINT_CODES

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "opentide"

#: Where validation and lint findings get their codes.
_EMITTERS = (
    *sorted((SRC / "validation").rglob("*.py")),
    SRC / "sharing" / "config.py",
    SRC / "states" / "deployment.py",
    SRC / "loading" / "object_loader.py",
    SRC / "registry" / "builder.py",
    SRC / "cli" / "services" / "lint.py",
)
_LITERAL = re.compile(r"""\bcode\s*=\s*"([a-z_]+)"|"code":\s*"([a-z_]+)\"""")
_NAMED = re.compile(r"\bcode\s*=\s*([A-Z_]+)\b")
_STATE_ERROR = re.compile(r"""DeploymentStateError\(\s*"([a-z_]+)\"""")
#: ``_string_list(..., "object_type_unknown", ...)`` passes the code positionally.
_UNKNOWN_CODE = re.compile(r"""^\s*"([a-z_]+_unknown)",$""", re.MULTILINE)

runner = CliRunner()


def emitted_codes() -> set[str]:
    """Every code a validation or lint finding can carry, read from the source."""
    codes = set(LINT_CODES.values())
    for path in _EMITTERS:
        text = path.read_text(encoding="utf-8")
        codes.update(next(group for group in match if group) for match in _LITERAL.findall(text))
        codes.update(_STATE_ERROR.findall(text))
        if path.name == "config.py":
            codes.update(_UNKNOWN_CODE.findall(text))
        for name in _NAMED.findall(text):
            if name == "LINT_CODES":
                continue  # code=LINT_CODES["…"]: its values are in already
            constant = re.search(rf'^{name}\s*=\s*"([a-z_]+)"', text, re.MULTILINE)
            entry = re.search(rf'^{name}\s*=\s*LINT_CODES\["([a-z_]+)"\]', text, re.MULTILINE)
            assert constant or entry, f"{path}: code={name} is not a string constant in that file"
            codes.add(constant.group(1) if constant else LINT_CODES[entry.group(1)])
    return codes


def test_the_scan_finds_the_codes_it_protects() -> None:
    codes = emitted_codes()
    assert len(codes) >= 30
    assert {
        "invalid_ref",
        "vocab_unknown",
        "schema_validation",
        "yaml_parse",
        "invalid_uuid",
        "duplicate_id",
        "invalid_cve",
        "scope_no_match",
        "external_id_in_rule",
        "deprecated_field",
        "config_enum_unknown",
        "chaining_relation_unknown",
        "platform_not_enabled",
        "object_type_unknown",
        "external_id_shape",
        "missing_uuid",
        "schema_missing",
        "placeholder",
    } <= codes


#: Every code a finding of ``validate`` or ``lint`` can carry, from the tables
#: that decide each check's status.
REGISTERED = VALIDATION_CODES | set(LINT_CODES.values())


def test_every_registered_code_has_a_page() -> None:
    missing = sorted(REGISTERED - set(diagnostic_codes()))
    assert not missing, f"add src/opentide/data/diagnostics/<code>.md for: {missing}"


def failure_codes() -> set[str]:
    """Every ``failure.code`` the CLI sets, read from where each one is defined or set."""
    from opentide.cli.services import share
    from opentide.cli.ui import contract
    from opentide.core.errors import UserFileError

    codes = {
        value
        for name, value in vars(contract).items()
        if name.isupper() and isinstance(value, str) and name != "SCHEMA_VERSION"
    }
    codes |= set(share._RUN_FAILURE_CODES.values()) | set(share._PREFLIGHT)
    codes |= {error.code for error in UserFileError.__subclasses__()}
    texts = [path.read_text(encoding="utf-8") for path in (SRC / "cli").rglob("*.py")]
    # ``PATH_EXISTS = "path_exists"`` … ``code=PATH_EXISTS``: a code set through a
    # module constant, wherever the constant is defined.
    constants = {
        name: value
        for text in texts
        for name, value in re.findall(r'^([A-Z][A-Z0-9_]*)\s*=\s*"([a-z_]+)"$', text, re.MULTILINE)
    }
    for text in texts:
        codes.update(re.findall(r'"_failure_code"\]?\s*[:=]\s*"([a-z_]+)"', text))
        codes.update(re.findall(r'\bcode="([a-z_]+)"', text))
        for name in re.findall(
            r'(?:\bcode=|"_failure_code"\]?\s*[:=]\s*)([A-Z][A-Z0-9_]*)\b', text
        ):
            if name in constants:
                codes.add(constants[name])
    return codes


def doctor_check_codes() -> set[str]:
    """The ``code`` of every ``opentide doctor`` check (``Check("python_version", …)``)."""
    text = (SRC / "cli" / "services" / "doctor.py").read_text(encoding="utf-8")
    return set(re.findall(r'\bCheck\(\s*"([a-z_]+)"', text))


def compile_codes() -> set[str]:
    """The ``error[compile_*]`` codes a deploy dry run prints for a rule it cannot compile."""
    return {
        code
        for path in SRC.rglob("*.py")
        for code in re.findall(r'"(compile_[a-z_]+)"', path.read_text(encoding="utf-8"))
    }


def test_the_doctor_and_compile_scans_find_the_codes_they_protect() -> None:
    assert {
        "python_version",
        "opentide_version",
        "opentide_latest",
        "workspace",
        "git",
        "git_repository",
        "configuration",
        "templates_fresh",
        "schemas_fresh",
        "platforms_enabled",
        "platform_sdk",
        "credentials",
        "proxy",
        "vscode_settings",
        "vscode_snippets",
        "mcp_config",
    } <= doctor_check_codes()
    assert {"compile_empty_block", "compile_missing_field", "compile_failed"} <= compile_codes()


def test_every_doctor_check_and_compile_code_has_a_page() -> None:
    """``opentide explain`` covers what doctor and a deploy dry run print, too."""
    missing = sorted((doctor_check_codes() | compile_codes()) - set(diagnostic_codes()))
    assert not missing, f"add src/opentide/data/diagnostics/<code>.md for: {missing}"


def test_the_failure_scan_finds_the_codes_it_protects() -> None:
    assert {
        "issues_found",
        "usage_unknown_command",
        "command_failed",
        "no_tenant_reached",
        "needs_human_decision",
        "not_implemented",
        "share_partial",
        "api_key_unset",
        "config_parse",
        "yaml_parse",
        "internal",
        "path_exists",
        "reference_not_found",
        "template_missing",
        "workspace_not_found",
        "doctor_checks_failed",
        "usage_tui_needs_tty",
    } <= failure_codes()


def test_every_failure_code_has_a_page() -> None:
    """Principle 4: every failure has a code and an ``opentide explain`` page (D15)."""
    missing = sorted(failure_codes() - set(diagnostic_codes()))
    assert not missing, f"add src/opentide/data/diagnostics/<code>.md for: {missing}"


def test_every_code_in_the_source_is_registered() -> None:
    """The scan is the safety net: a new code must be in the check table too."""
    unregistered = sorted(emitted_codes() - REGISTERED)
    assert not unregistered, (
        "register these codes in _CHECK_ISSUE_CODES or _CHECK_WARNING_CODES "
        f"(src/opentide/cli/services/validation.py): {unregistered}"
    )


def test_the_table_covers_what_the_scan_cannot_see() -> None:
    """``code="missing_field" if … else "name_invalid"`` hides the second code from the scan."""
    assert "name_invalid" in REGISTERED
    assert "name_invalid" in diagnostic_codes()


def test_explain_ignores_case() -> None:
    page = load_page("VOCAB_UNKNOWN ")
    assert page is not None and page.code == "vocab_unknown"


@pytest.mark.parametrize("code", diagnostic_codes())
def test_every_page_has_a_summary_an_example_and_a_fix(code: str) -> None:
    page = load_page(code)
    assert page is not None
    assert page.markdown.startswith(f"# {code}\n\n")
    assert page.summary and page.summary.endswith(".")
    assert "\n## Example\n" in page.markdown
    assert "\n## How to fix\n" in page.markdown


def test_the_reference_page_is_generated_from_the_pages() -> None:
    committed = (ROOT / REFERENCE_PAGE).read_text(encoding="utf-8")
    assert committed == reference_markdown(), (
        "docs/cli/diagnostics.md is stale: run "
        "uv run python scripts/build/render_diagnostics_docs.py"
    )


@pytest.mark.parametrize("code", ["", "../README", "vocab_unknown.md", "nope", "../VOCAB_UNKNOWN"])
def test_only_a_page_name_loads(code: str) -> None:
    assert load_page(code) is None


def test_explain_prints_the_page() -> None:
    result = runner.invoke(app, ["--no-color", "explain", "vocab_unknown"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("# vocab_unknown\n\nA value is not in the vocabulary")
    assert "## How to fix" in result.stdout


def test_explain_json_carries_the_page() -> None:
    result = runner.invoke(app, ["--json", "explain", "invalid_ref"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["code"] == "invalid_ref"
    assert payload["meaning"] == "A reference names an object that does not exist."
    assert payload["markdown"].startswith("# invalid_ref")
    assert payload["ok"] is True


def test_an_unknown_code_is_a_usage_error_with_a_suggestion() -> None:
    result = runner.invoke(app, ["--json", "explain", "vocab_unknwn"])
    assert result.exit_code == 2
    failure = json.loads(result.stdout)["failure"]
    assert failure["code"] == "usage_invalid_choice"
    assert failure["suggestion"] == "vocab_unknown"


def test_explain_without_a_code_lists_them() -> None:
    result = runner.invoke(app, ["--json", "explain"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [item["code"] for item in payload["codes"]] == diagnostic_codes()
    assert payload["summary"] == {"codes": len(diagnostic_codes())}
    human = runner.invoke(app, ["--no-color", "explain"])
    assert human.exit_code == 0, human.output
    assert any(line.startswith("yaml_parse ") for line in human.stdout.splitlines())
    assert human.stdout.endswith(f"✓ {len(diagnostic_codes())} diagnostic codes\n")
